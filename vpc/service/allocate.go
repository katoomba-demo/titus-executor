package service

import (
	"context"
	"database/sql"
	"fmt"
	"net"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/golang/protobuf/proto"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"github.com/pborman/uuid"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
	"golang.org/x/crypto/ed25519"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// this is the maximum number of IP addresses you are allowed to assign to an interface in EC2.
const maxAddressesPerInterface = 50

// The dummy interface is used for IP addresses that are allocated
const dummyInterfaceDescription = "titus-dummy"
const dummyInterfaceHostnameTag = "titusvpcservice-hostname"

var (
	errAllocationNotFound = status.Error(codes.NotFound, "Could not find allocation")
)

// This must be called with the dummy service lock held
func (vpcService *vpcService) getDummyInterface(ctx context.Context, ec2session ec2wrapper.EC2Session, subnet *ec2.Subnet) (ec2wrapper.EC2NetworkInterfaceSession, *ec2.NetworkInterface, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "getDummyInterface")
	defer span.End()

	// We need to create / allocate a new dummy interface and keep track of it
	// TODO(Sargun): Write some code to recycle dummy interfaces, maybe?
	session, err := ec2session.Session(ctx)
	if err != nil {
		span.SetStatus(trace.Status{
			Code:    trace.StatusCodeUnknown,
			Message: err.Error(),
		})
		return nil, nil, err
	}

	ec2client := ec2.New(session)

	key := aws.StringValue(subnet.SubnetId)
	if dummyInterfaceSession, ok := vpcService.dummyInterfaceSessions[key]; ok {
		dummyInterface := vpcService.dummyInterfaces[key]
		// TODO(Sargun): Come up with a better timeout here.
		logger.G(ctx).WithField("interface", dummyInterface.String()).Debug("Retrieved interface from prior allocation")
		// TODO: Reallocate if the dummy interface's private IP address count has exceeded some value
		return dummyInterfaceSession, dummyInterface, nil
	}

	// Let's see if we can find another interface. We can only look for interfaces that used to belong to this node, because of the concurrency problem
	// TODO(Sargun): Do this at startup time
	describeNetworkInterfacesInput := ec2.DescribeNetworkInterfacesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("tag:" + dummyInterfaceHostnameTag),
				Values: aws.StringSlice([]string{vpcService.hostname}),
			},
			{
				Name:   aws.String("description"),
				Values: aws.StringSlice([]string{dummyInterfaceDescription}),
			},
			{
				Name:   aws.String("subnet-id"),
				Values: []*string{subnet.SubnetId},
			},
		},
		MaxResults: aws.Int64(1000),
	}
	networkInterfaces := []*ec2.NetworkInterface{}
	for {
		describeNetworkInterfacesOutput, err := ec2client.DescribeNetworkInterfacesWithContext(ctx, &describeNetworkInterfacesInput)
		if err != nil {
			return nil, nil, ec2wrapper.HandleEC2Error(err, span)
		}
		networkInterfaces = append(networkInterfaces, describeNetworkInterfacesOutput.NetworkInterfaces...)
		if describeNetworkInterfacesOutput.NextToken == nil {
			break
		}
		describeNetworkInterfacesInput.NextToken = describeNetworkInterfacesOutput.NextToken
	}

	for idx := range networkInterfaces {
		ni := networkInterfaces[idx]
		if len(ni.PrivateIpAddresses) < maxAddressesPerInterface && len(ni.Ipv6Addresses) < maxAddressesPerInterface {
			// We can recycle this.
			logger.G(ctx).WithField("eni", ni.String()).Info("Found ENI, performing crash recovery")
			span.AddAttributes(trace.BoolAttribute("crash-recovered", true))

			dummyInterfaceSession, err := vpcService.ec2.GetSessionFromNetworkInterface(ctx, ec2session, ni)
			if err != nil {
				span.SetStatus(trace.Status{
					Code:    trace.StatusCodeUnknown,
					Message: err.Error(),
				})
				return nil, nil, err
			}

			vpcService.dummyInterfaceSessions[key] = dummyInterfaceSession
			vpcService.dummyInterfaces[key] = ni
			logger.G(ctx).WithField("interface", ni.String()).Info("Performed interface crash recovery")
			return dummyInterfaceSession, ni, nil
		}

	}
	span.AddAttributes(trace.BoolAttribute("crash-recovered", false))
	return vpcService.createDummyInterface(ctx, ec2session, subnet, ec2client, key)
}

func (vpcService *vpcService) createDummyInterface(ctx context.Context, ec2session ec2wrapper.EC2Session, subnet *ec2.Subnet, ec2client *ec2.EC2, key string) (ec2wrapper.EC2NetworkInterfaceSession, *ec2.NetworkInterface, error) {
	ctx, span := trace.StartSpan(ctx, "createDummyInterface")
	defer span.End()

	dummyNetworkInterface, err := ec2client.CreateNetworkInterfaceWithContext(ctx, &ec2.CreateNetworkInterfaceInput{
		Description:      aws.String(dummyInterfaceDescription),
		Groups:           nil,
		Ipv6AddressCount: aws.Int64(0),
		SubnetId:         subnet.SubnetId,
	})
	if err != nil {
		return nil, nil, ec2wrapper.HandleEC2Error(err, span)
	}

	_, err = ec2client.CreateTagsWithContext(ctx, &ec2.CreateTagsInput{
		Resources: []*string{dummyNetworkInterface.NetworkInterface.NetworkInterfaceId},
		Tags: []*ec2.Tag{
			{
				Key:   aws.String(dummyInterfaceHostnameTag),
				Value: aws.String(vpcService.hostname),
			},
		},
	})
	if err != nil {
		return nil, nil, ec2wrapper.HandleEC2Error(err, span)
	}

	dummyInterfaceSession, err := vpcService.ec2.GetSessionFromNetworkInterface(ctx, ec2session, dummyNetworkInterface.NetworkInterface)
	if err != nil {
		span.SetStatus(trace.Status{
			Code:    trace.StatusCodeUnknown,
			Message: err.Error(),
		})
		return nil, nil, err
	}

	vpcService.dummyInterfaceSessions[key] = dummyInterfaceSession
	vpcService.dummyInterfaces[key] = dummyNetworkInterface.NetworkInterface
	return dummyInterfaceSession, dummyNetworkInterface.NetworkInterface, nil
}

func (vpcService *vpcService) AllocateAddress(ctx context.Context, rq *titus.AllocateAddressRequest) (*titus.AllocateAddressResponse, error) {
	// 1. We get the subnet
	// 2. We allocate an IP
	// 3. Do the cryptography dance
	// 4. Store it in the database.
	// 5. Return it to the user
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "allocateAddress")
	defer span.End()

	log := ctxlogrus.Extract(ctx)
	ctx = logger.WithLogger(ctx, log)

	if rq.AccountId == "" {
		return nil, status.Error(codes.InvalidArgument, "AccountId must be specified")
	}
	if rq.AddressAllocation == nil {
		return nil, status.Error(codes.InvalidArgument, "AddressAllocation must be specified")
	}
	if rq.AddressAllocation.AddressLocation == nil {
		return nil, status.Error(codes.InvalidArgument, "AddressAllocation.AddressLocation must be specified")
	}

	if rq.AddressAllocation.Address != "" {
		return nil, status.Error(codes.InvalidArgument, "AddressAllocation.Address must be unset")
	}

	if rq.Family != titus.Family_FAMILY_V4 {
		return nil, status.Errorf(codes.Unimplemented, "Address family %s not yet implemented", rq.Family.String())
	}

	if rq.AddressAllocation.AddressLocation.SubnetId == "" {
		return nil, status.Error(codes.InvalidArgument, "Subnet ID must be specified")
	}

	allocationUUID := rq.AddressAllocation.Uuid
	if allocationUUID == "" {
		allocationUUID = uuid.New()
	}
	session, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, rq.AccountId, rq.AddressAllocation.AddressLocation.Region)
	if err != nil {
		return nil, err
	}

	logger.WithFields(ctx, map[string]interface{}{
		"family":   rq.Family,
		"region":   rq.AddressAllocation.AddressLocation.Region,
		"az":       rq.AddressAllocation.AddressLocation.AvailabilityZone,
		"subnetId": rq.AddressAllocation.AddressLocation.SubnetId,
	})
	logger.G(ctx).Info("Performing Address allocation")

	subnet, err := session.GetSubnetByID(ctx, rq.AddressAllocation.AddressLocation.SubnetId, ec2wrapper.UseCache)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not get subnet")
		return nil, err
	}

	if aws.StringValue(subnet.AvailabilityZone) != rq.AddressAllocation.AddressLocation.GetAvailabilityZone() {
		return nil, status.Errorf(codes.InvalidArgument, "Subnet %q is in availability zone %q, while specified address location is in availability zone %q", aws.StringValue(subnet.SubnetId), aws.StringValue(subnet.AvailabilityZone), rq.AddressAllocation.AddressLocation.AvailabilityZone)
	}

	vpcService.dummyInterfaceLock.Lock()
	defer vpcService.dummyInterfaceLock.Unlock()

	dummyNetworkInterfaceSession, dummyNetworkInterface, err := vpcService.getDummyInterface(ctx, session, subnet)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not get dummy interface")
		return nil, err
	}

	awsSession, err := dummyNetworkInterfaceSession.Session(ctx)
	if err != nil {
		return nil, ec2wrapper.HandleEC2Error(err, span)
	}

	logger.G(ctx).WithField("networkInterfaceId", aws.StringValue(dummyNetworkInterface.NetworkInterfaceId)).Info("Got network interface")

	tx, err := vpcService.conn.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "Could not start database transaction")
	}
	defer func() {
		_ = tx.Rollback()
	}()

	rows, err := tx.QueryContext(ctx, "SELECT id FROM ip_addresses WHERE id = $1 FOR UPDATE LIMIT 1", allocationUUID)
	if err != nil {
		return nil, errors.Wrap(err, "Could not query database for existing records")
	}
	defer rows.Close()
	if rows.Next() {
		return nil, status.Errorf(codes.AlreadyExists, "UUID %s is already allocated", allocationUUID)
	}

	assignPrivateIPAddressesOutput, err := dummyNetworkInterfaceSession.AssignPrivateIPAddresses(ctx, ec2.AssignPrivateIpAddressesInput{
		SecondaryPrivateIpAddressCount: aws.Int64(1),
	})
	if err != nil {
		return nil, ec2wrapper.HandleEC2Error(err, span)
	}

	if count := len(assignPrivateIPAddressesOutput.AssignedPrivateIpAddresses); count != 1 {
		return nil, status.Errorf(codes.Internal, "Instead of receiving 1 IP upon allocation from AWS, received: %d", count)
	}

	ip := net.ParseIP(aws.StringValue(assignPrivateIPAddressesOutput.AssignedPrivateIpAddresses[0].PrivateIpAddress))
	az := aws.StringValue(dummyNetworkInterface.AvailabilityZone)

	ec2session := ec2.New(awsSession)
	_, err = ec2session.CreateTagsWithContext(ctx, &ec2.CreateTagsInput{
		DryRun:    nil,
		Resources: []*string{dummyNetworkInterface.NetworkInterfaceId},
		Tags: []*ec2.Tag{
			{
				Key:   aws.String(fmt.Sprintf("vpc-service:%s", allocationUUID)),
				Value: aws.String(ip.String()),
			},
		},
	})
	if err != nil {
		return nil, ec2wrapper.HandleEC2Error(err, span)
	}

	allocation := &titus.AddressAllocation{
		AddressLocation: &titus.AddressLocation{
			Region:           az[0 : len(az)-1],
			AvailabilityZone: az,
			SubnetId:         aws.StringValue(dummyNetworkInterface.SubnetId),
		},
		Uuid:    allocationUUID,
		Address: ip.String(),
	}

	bytes, err := proto.Marshal(allocation)
	if err != nil {
		return nil, errors.Wrap(err, "Cannot serialize allocation")
	}

	signature := ed25519.Sign(vpcService.hostPrivateKey, bytes)

	region := az[:len(az)-1]
	_, err = tx.ExecContext(ctx,
		`INSERT INTO ip_addresses(id, az, region, subnet_id, ip_address, home_eni, host_public_key, host_public_key_signature, message, message_signature) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		allocationUUID,
		az,
		region,
		aws.StringValue(subnet.SubnetId),
		ip.String(),
		aws.StringValue(dummyNetworkInterface.NetworkInterfaceId),
		vpcService.hostPublicKey,
		vpcService.hostPublicKeySignature,
		bytes,
		signature,
	)
	if err != nil {
		return nil, errors.Wrap(err, "Could not persist allocation")
	}
	err = tx.Commit()
	if err != nil {
		return nil, errors.Wrap(err, "Could not commit transaction")
	}
	resp := &titus.AllocateAddressResponse{
		SignedAddressAllocation: &titus.SignedAddressAllocation{
			AddressAllocation:      allocation,
			AuthoritativePublicKey: vpcService.authoritativePublicKey,
			HostPublicKey:          vpcService.hostPublicKey,
			HostPublicKeySignature: vpcService.hostPublicKeySignature,
			Message:                bytes,
			MessageSignature:       signature,
		},
	}

	return resp, nil
}

func (vpcService *vpcService) GetAllocation(ctx context.Context, rq *titus.GetAllocationRequest) (*titus.GetAllocationResponse, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	log := ctxlogrus.Extract(ctx)
	ctx = logger.WithLogger(ctx, log)
	var rows *sql.Rows
	var err error
	switch v := rq.GetSearchParameter().(type) {
	case *titus.GetAllocationRequest_Address:
		rows, err = vpcService.conn.QueryContext(ctx, "SELECT id, az, region, subnet_id, ip_address FROM ip_addresses WHERE ip_address = $1", v.Address)

	case *titus.GetAllocationRequest_Uuid:
		rows, err = vpcService.conn.QueryContext(ctx, "SELECT id, az, region, subnet_id, ip_address FROM ip_addresses WHERE id = $1", v.Uuid)
	}
	if err != nil {
		return nil, errors.Wrap(err, "Could not run SQL query")
	}

	if !rows.Next() {
		return nil, errAllocationNotFound
	}
	var id, az, region, subnetid, ipaddress string
	err = rows.Scan(&id, &az, &region, &subnetid, &ipaddress)
	if err == sql.ErrNoRows {
		return nil, errAllocationNotFound
	}
	if err != nil {
		return nil, errors.Wrap(err, "Could not deserialize row")
	}

	return &titus.GetAllocationResponse{
		AddressAllocation: &titus.AddressAllocation{
			AddressLocation: &titus.AddressLocation{
				Region:           region,
				AvailabilityZone: az,
				SubnetId:         subnetid,
			},
			Uuid:    id,
			Address: ipaddress,
		},
	}, nil
}
