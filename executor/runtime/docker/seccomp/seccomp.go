// Code generated by go-bindata.
// sources:
// default.json
// nested-container.json
// fuse-container.json
// DO NOT EDIT!

package seccomp

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func bindataRead(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}
	if clErr != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type asset struct {
	bytes []byte
	info  os.FileInfo
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (fi bindataFileInfo) Name() string {
	return fi.name
}
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}
func (fi bindataFileInfo) IsDir() bool {
	return false
}
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _defaultJson = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xe4\x5a\x5d\x4f\x1c\x3b\xd2\xbe\x1e\x7e\x05\x9a\xeb\x5c\x10\x42\x38\x24\x77\xf3\x12\xde\x4d\xb4\x21\x64\x81\xd5\x39\x47\xab\xc8\x32\xee\xea\x1e\xef\xf8\x0b\x97\x7b\x60\x14\xe5\xbf\xaf\xdc\x3d\xd3\x2e\xbb\xe7\x44\x99\x90\xc0\xae\x72\x01\xf2\xf3\xb8\x6c\x57\x95\xed\x72\xd9\x3d\x9f\xf7\x26\xd3\x0a\x6a\xde\xaa\x30\x13\x41\x5a\x33\x7d\xbd\x3f\xbd\x3a\x3d\xff\xc8\x66\xa7\xd7\xec\xec\xf2\xf2\xc3\xc5\xf4\xd9\xde\x64\xca\xbd\x98\x9f\x73\x37\x7d\xbd\xff\xaf\xbd\xc9\xe4\xf3\xde\x64\xd2\x73\x32\x80\x08\xad\x87\xd4\xec\xf2\xf4\x2d\xfb\xe3\xe4\x98\x1d\x1f\xc5\x86\x93\xc9\x14\xdb\x9b\x19\x91\xc4\x75\x1f\x93\x49\xde\xa0\x97\xce\xc8\x17\x87\xd3\xc8\x7d\xda\x9b\x4c\xbe\x3c\xfb\x86\x61\x67\xf1\xff\x4e\xe3\xce\x2e\xcf\x77\x1b\xe2\xfc\xdd\xc7\xab\x9d\x46\x88\x0d\xc6\xa6\xf5\xdd\x7c\xd8\xd5\xc0\xd4\xec\xc7\x28\xb0\xfb\xe8\x67\xef\x77\xb6\xfe\xec\xfd\xf6\xe1\x63\x57\xdf\xe5\x81\x4d\xc3\x1f\xa7\xc6\x6e\x3a\x5c\xbd\x78\x75\xf0\xc7\x0e\xa3\x47\xf9\x34\xc2\xde\xe4\x53\xdc\x50\xb8\x42\xc1\x95\xc2\x6c\x47\x19\xae\x69\x17\x5c\x08\x70\x61\xa3\x76\x8f\x8e\x28\x44\x1c\x50\xf5\xef\x20\x35\xdc\x0f\x58\x71\xaf\x37\xe0\x46\x9a\x6a\x28\xfb\xc5\xa6\x28\xb8\x6b\x20\x10\x84\x04\xcd\x2b\xe9\x13\xd0\xb6\x4a\xc0\xde\x99\x0c\x6c\xa6\x62\x32\x15\xca\x8a\x05\x6b\x20\x44\x4f\x94\x5c\xd4\x2f\x27\x0d\x37\x16\x15\x80\x23\x34\x26\x19\x6b\x0c\x88\xa4\x91\x75\x2b\x56\x4b\x05\xcc\x73\xd3\x24\x29\x0f\x7c\x90\xa9\x5a\x47\x8a\x87\xa4\xfc\x62\x53\x06\x67\x95\x62\x5d\x2b\xd8\xc6\x3d\x2f\xc8\xa0\x46\x04\xb3\xaa\xca\x49\x77\xc7\x65\xc8\xa9\xed\x4c\xd6\x74\x09\x26\xd4\x25\x1c\x94\x86\x7b\x10\x4b\xc8\x51\xb2\x14\xee\x65\x56\x66\x8d\xb7\xc9\xf8\xba\x5f\x1c\x49\xbc\xe6\xd5\x52\x22\x1c\x1f\x8d\x08\x46\x39\xa5\xac\x20\x7e\xa9\xb9\xb1\x41\xd6\x2b\xa6\x79\x5a\x35\x75\xb6\x34\xea\x6c\x6d\xf4\x88\x0c\x9b\x2d\x96\xba\x58\x2d\x3d\xa6\xd2\x26\x79\xbb\x03\x44\xb7\x8a\x07\x8e\x2b\x23\x06\xa2\x81\x70\xcf\x43\x48\x9a\x28\x89\x25\x63\x45\x52\xdb\x12\x13\x3c\x68\xbb\x84\x5c\x18\xcb\xfe\x30\x10\xd5\x22\x20\xda\x44\x38\x22\x6a\x2c\x20\xad\xa7\xaa\x07\xdf\x9a\xcc\xcf\x1b\x82\x34\x68\x43\xda\xcc\x75\x1b\xf7\x0e\x99\xce\x06\x82\x70\x2d\x45\x77\x15\x41\x15\x98\x80\x25\x4e\x7d\x37\x10\xa0\x91\x55\x01\xd3\xbc\x44\xa2\xcd\xeb\xdb\xa2\x3e\x6f\x5e\xb6\xee\xd6\x22\x8e\x88\x4c\x46\x46\x93\x3c\x21\x1c\x80\x8f\xf1\x8f\x52\xf9\x30\xae\xf1\x8e\xc2\xbc\xb2\x80\x5e\x5a\x2f\xc3\x8a\x50\x9e\x9b\xca\x6a\x4a\x00\xe6\x03\xf4\x44\xa6\xa6\x07\x6c\x4b\x99\xd2\x19\x5e\x49\x2d\xe9\xdc\x30\x6f\x6f\x5a\x0c\x2c\xae\x48\x2a\xd7\x22\x6f\xa8\x7d\x98\xf5\x8c\x56\x2c\x0a\x07\x44\xca\xba\xac\xeb\x30\xf7\xc0\x2b\xc6\x3d\x70\x42\x87\xac\xa7\xe8\x5a\x5b\x57\x9c\x5a\x9f\x5b\x51\x9a\x90\xad\x7c\xb9\xde\xf5\xbc\xaa\xd8\x1d\x0f\x62\x5e\x56\x48\x93\xcc\xa5\xdc\xf3\x92\xf4\xba\xe8\xc0\x32\xc1\x8d\x00\x95\x08\x12\x60\xa5\x65\x15\x60\xf0\x76\x45\x98\xb8\xfa\x96\x74\x3d\x4b\x1b\xe7\x96\x91\x93\x6b\xcd\x20\x65\x22\x4a\xf1\x30\xe2\xf6\x86\x4c\x92\x74\xc3\x6e\x5c\x48\x35\x68\xa0\xb2\x78\xa5\x8a\x78\xa5\x4a\x47\x29\x69\x16\xb4\x9c\x36\x68\x9c\x79\x30\x14\xe5\x0d\x47\x0c\x53\x0a\x01\x52\x6f\x5b\x22\x54\x2e\x50\x86\x2b\x45\xc3\x95\xca\xc3\x95\xee\x83\xfd\x00\x41\xd7\x55\x71\x04\x6a\x69\x84\xf5\x09\x2e\x48\x8c\xef\x40\xea\x5c\x2f\x4c\x8a\xf8\x1d\x20\x75\x34\xe4\x76\xe0\x30\x43\x3c\xf9\x5a\x6b\xee\x68\x39\x09\x3a\x6f\x03\x39\xf8\xf5\x6d\x9c\x6c\x84\x40\xcd\xd5\xb7\xac\x5f\x63\x84\xb0\x2e\xb9\x5c\xdf\xb2\xb8\x0b\x2a\x0f\x02\x64\x3a\x46\x37\x34\x42\xca\x88\xf4\x2d\x6b\x0d\x9d\x4a\xed\x81\xea\x86\x0d\x59\xa3\x1a\x1b\xb2\xf2\x34\x36\x5e\x2c\x09\x42\xd2\x2d\x0d\xf9\xba\x35\x99\x67\x7a\x48\xbd\xd1\x1a\x32\xe6\x28\x31\x32\x70\xb7\x3e\x73\x86\x05\x63\xe0\x0e\x41\x11\x3f\x51\xf3\x63\x39\xc9\x3a\xde\xa6\xd9\x77\xd2\x65\xe5\xc1\xef\x31\x49\x19\xca\x19\xf0\xc4\x01\x2e\x86\x9f\xb4\xb4\x3a\xb8\xcc\x51\xea\xb1\x8f\x8c\x44\xba\xd7\x78\xb8\xeb\xb9\x3b\x2f\xe9\xa9\xd7\xe3\x65\x01\x87\xfe\x62\xef\xb4\xcc\xe7\x05\x41\x67\x71\x83\x93\x1b\x32\x55\x3d\x88\xac\x5c\xfb\x74\x36\x44\xac\x35\x36\x19\xa6\x50\x73\xd7\xa7\xa2\x8e\x37\x29\xd3\xdd\xb2\x67\x3d\xd0\x88\xde\x23\xaa\x50\x8f\x89\x81\x18\xb8\x0f\x6c\x7d\x39\x18\x68\x4d\x76\x63\xac\x96\x0d\xef\x2f\xeb\x19\xe7\xc0\x54\xd2\x34\x05\xe9\xad\xd0\x1c\x17\x39\x7b\xdb\x42\x0b\xd2\xd4\x36\xa7\x3d\x84\xd6\x17\xbd\x62\x8b\x8e\xec\x96\x9e\xec\x36\x11\x4d\x71\x7d\x60\xa1\xd9\xd6\x31\x8a\x39\x54\x71\x03\xf3\xba\x8e\x67\xc4\x6a\x5c\x41\xfc\x35\x90\x8e\x7b\xae\x47\x2c\xdb\x1c\xeb\x4c\xf3\xfb\xaf\xd5\x4a\x33\xaa\xed\x0a\xad\x82\x62\x2c\xef\xbb\xa6\xd2\x04\xf0\x4b\xae\xf2\x4a\xfc\x2b\xb5\x71\x9b\xda\xb8\x55\x6d\xfc\xcb\xa1\x57\x12\xd2\x6d\x00\x41\x08\xab\x5d\x82\x74\x6b\x23\x68\xb2\x05\x11\x34\x89\x41\x08\xda\x92\x66\xba\x9b\x1a\xca\x98\x8a\x96\xe3\xb2\x2d\x71\xda\x80\x91\xa1\x2b\xbf\xc3\x39\x0c\x69\x6a\x21\xd4\x34\x83\xda\xe0\x74\x62\x76\x4c\x5b\x48\xb4\x85\x44\xde\x43\xd9\x3e\xcf\x25\x71\x9c\x4b\x62\x99\x4b\x62\x9e\x38\xe2\x38\x19\xc4\x98\xc6\xe5\x22\x1e\xca\x81\xf3\xec\x10\xc7\xd9\x21\x96\xd9\x21\x8e\xb3\xc3\x8e\x2a\x45\x46\x12\x59\xfe\x88\xdb\xf3\x47\xcc\xd2\x45\x1c\xe5\x86\xb8\x3d\x37\xec\x68\x59\xc5\x5c\xce\x93\xe7\x02\xcc\x12\x42\x2c\x12\xc2\x32\xb7\xc0\xb9\x4e\x41\x0b\xe7\xd9\x5a\x9c\xeb\x8a\x56\xd1\x85\x39\x6f\x43\x45\xd2\xa9\x18\xb5\x54\xc0\xc0\xd3\x39\x88\xb2\x31\x5c\xa5\x3b\xf0\x06\x1f\x11\x22\x8f\x49\xd1\x6a\x32\x44\x87\x68\xa8\xec\x19\xc7\x53\xbc\x44\xa7\xa4\x48\x4b\x9e\x1c\xa1\x79\x92\x94\xdf\xe0\xca\x0b\x1c\xae\x34\x3d\x5c\xd6\x90\xf4\x45\x0e\xfb\x58\xde\xf2\x52\x11\x69\x32\xc0\x0a\xb3\x30\xb9\x42\x65\x87\x7d\x16\x60\x68\x15\x1a\x9a\xa0\xd2\x37\x94\x6e\xd1\x17\x69\x5c\xcf\x55\xa0\xa0\xe0\x46\x09\xdf\x86\x2d\x1e\x66\x36\x34\x6e\xa1\xa3\xac\x5d\x82\xf7\xad\x19\xf1\x63\xe1\x2d\x3d\x0c\xc6\x87\xcc\xa6\xe2\x36\x3c\xbe\x0c\xb7\xa3\x4b\x56\x4b\x8f\xb4\x96\x9e\xb1\x79\x2a\xd7\xa3\x34\x4d\x2d\x55\xa9\x03\x06\x8b\xda\x41\xc9\x25\x7d\x32\x58\xea\x7c\x1d\xc5\xb3\xef\x88\x82\xb4\x9b\x22\x22\x97\xd1\x2e\x87\xc9\xc0\xb2\x7f\x0c\xec\xa8\x29\x1f\xbf\xba\xcf\xde\xbf\xbf\xf8\x7d\xba\xae\xf6\x4d\xf7\x20\xb8\x96\x16\x56\x6b\x30\x21\x8a\xaf\x05\xa4\x11\xaa\xad\xba\x57\xc3\xcf\x5f\x7a\x0a\xee\x09\x95\x3f\x6a\x16\x0f\x8c\x0e\x3c\x5a\xc3\x55\x8c\x8d\xbb\xeb\xd4\xf5\xd1\xf5\xdb\xe9\x51\xc1\xfd\xf4\xf5\xfe\xc1\xb3\x35\xb1\xe4\xaa\x85\x11\x71\x7d\x67\x29\x67\xdd\x30\x4a\xfc\x3b\xfb\x47\xa7\xc6\xe4\x0b\x51\xe6\x7f\xd0\xe4\x93\x5f\xcf\xe4\xe7\x2f\x9e\x1f\xfc\x76\xf8\x6b\xda\x7d\xf2\x0b\x2e\xf1\xa3\xc3\x57\x47\xaf\x8e\x7f\x3b\x7c\xf5\xf2\xbf\xcb\xf6\xe2\xec\x3d\xfc\x59\xa1\xb6\x1f\x8d\x7b\x31\x27\xa3\xc7\x7b\xb3\x38\x3e\x52\xd0\x9b\xf9\x29\xfe\xdf\xd9\x02\xee\x35\xdb\xf6\x3a\x1f\xf9\xaf\x64\x16\x99\xd1\x6b\xfe\xc6\x03\x5f\x38\x2b\x0d\xf9\xc8\x23\xe6\x50\xab\x16\xe7\x59\x82\xa8\xf0\x91\xfd\x94\x3e\x4e\x75\xe5\xf5\x17\xb8\xef\xf6\x98\x98\xb3\xfe\x91\xe2\x91\xad\xd0\xe9\x25\x64\x32\xbd\x5f\x7f\xcb\xfc\x4e\x2b\xb4\xad\x64\xbd\x62\xaa\x0a\x4f\x6e\xc5\x50\x3e\x39\x7e\x88\x45\xf8\xe2\xd5\x01\x73\x42\x32\xad\xa5\x65\xf4\xf1\x26\xaf\xc9\x32\xa4\xae\xca\xb7\x26\xa6\x62\x4c\x1a\x0c\xfe\x91\xdd\x11\x15\x18\x3c\x10\xc1\xfd\x43\x7c\x60\x1d\x18\x76\xb3\x62\x73\x6e\x2a\x05\x8c\xff\xe4\xc9\x15\xdc\x51\x5b\x4e\x67\x1f\xd9\x9b\xd9\x29\xbb\x3c\x9b\xbd\x61\x57\x67\xb3\xcb\xd3\xb7\x0f\x31\xe6\xc6\xd5\x43\x20\x51\xd6\x8c\xbf\x13\xd2\x0f\x03\xca\xda\x45\xeb\x58\x25\xac\x5d\xc8\xf4\x00\x6b\xdb\x14\x8d\x62\xf7\x2c\x58\xe2\x9c\x67\xc3\x09\x56\xb3\xee\xd9\x3f\x7b\xd4\xbd\x6d\x6d\xe0\xd9\x43\x48\xa8\xac\xe6\xd2\xd0\x0b\x00\x42\x98\x5b\x0c\x05\x65\x30\x5d\x1d\xa8\x0a\x3d\x3a\x4c\xf7\x05\x9c\x73\x0f\x8f\x3e\x49\x57\x7f\x5e\xb1\xd9\x9b\xf3\x77\x1f\x1e\x32\x3d\xfd\x9c\xfc\xac\x13\xff\xf0\xe0\xe4\xe0\xe5\xc1\xcb\x93\x97\xc7\x3b\x9c\xf8\xe7\xb3\xab\xbf\x9f\xbd\xf9\x31\x07\xff\x37\x3b\xef\xd9\x77\xed\xec\xc7\x73\xed\xf3\x47\x74\x6d\x34\x73\xbf\x7b\x95\x84\x00\x7e\xdf\xfa\x0a\xbc\x34\xcd\x7e\x6d\xfd\x7e\x67\xd4\xbe\xc4\xfd\x4a\xd6\x35\x78\xd8\xec\x8a\x9f\x11\x25\x77\x5b\xf9\x5f\x9d\x0b\x0f\x37\xd6\x3e\x7e\x1c\x8d\x8a\xfe\xdf\xc5\xc5\xf5\x83\x76\xe8\xdc\x3f\x95\xea\xa7\x6f\x2f\x1f\xa8\x7c\xff\xaa\xc4\xb4\xad\xda\xf4\x84\x1c\x23\x7e\x41\xd5\x5b\xb8\xdb\x16\xfc\x6a\xc3\x3d\x85\xf9\xe7\x17\x6f\xfe\xf9\xfe\xec\x41\x59\xa6\x10\x4f\x33\x73\x1f\x67\xa7\xa7\x0f\x9a\xb8\x85\x48\xdf\x15\x9c\xb7\x02\x10\xd9\x52\xb3\xe2\xcb\xdd\xc0\x17\xdf\xe0\x82\xe7\xe2\x69\xe6\xec\xe3\xf5\xe5\xec\xf4\x41\x73\x26\xad\x23\xbf\x2e\x70\xe0\xf5\x93\x18\x72\x39\xfb\xfd\xdd\xc5\x83\x32\xe9\x2d\xbf\xe9\xc0\xf1\xef\xe9\x36\x4f\xae\x4f\x61\xe3\xf5\xbb\xf3\x07\x4d\xd5\x72\xce\x4d\xd3\xba\xa7\xd1\xfd\xfa\x4f\x76\x7a\xf1\xe1\xff\xdf\xfd\xed\x1b\x2c\xd8\x9b\x7c\xda\xfb\xf2\x9f\x00\x00\x00\xff\xff\x9b\x8d\xde\xf4\x37\x2d\x00\x00")

func defaultJsonBytes() ([]byte, error) {
	return bindataRead(
		_defaultJson,
		"default.json",
	)
}

func defaultJson() (*asset, error) {
	bytes, err := defaultJsonBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "default.json", size: 11575, mode: os.FileMode(493), modTime: time.Unix(1525732804, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _nestedContainerJson = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xe4\x5a\x5d\x4f\x1c\x3b\xd2\xbe\x1e\x7e\x05\x9a\xeb\x5c\x10\x42\x38\x24\x77\xf3\x12\xde\x4d\xb4\x21\x64\x81\xd5\x39\x47\xab\xc8\x32\xee\xea\x1e\xef\xf8\x0b\x97\x7b\x60\x14\xe5\xbf\xaf\xdc\x3d\xd3\x2e\xbb\xe7\x44\x99\x90\xc0\xae\x72\x01\xf2\xf3\xb8\x6c\x57\x95\xed\x72\xd9\x3d\x9f\xf7\x26\xd3\x0a\x6a\xde\xaa\x30\x13\x41\x5a\x33\x7d\xbd\x3f\xbd\x3a\x3d\xff\xc8\x66\xa7\xd7\xec\xec\xf2\xf2\xc3\xc5\xf4\xd9\xde\x64\xca\xbd\x98\x9f\x73\x37\x7d\xbd\xff\xaf\xbd\xc9\xe4\xf3\xde\x64\xd2\x73\x32\x80\x08\xad\x87\xd4\xec\xf2\xf4\x2d\xfb\xe3\xe4\x98\x1d\x1f\xc5\x86\x93\xc9\x14\xdb\x9b\x19\x91\xc4\x75\x1f\x93\x49\xde\xa0\x97\xce\xc8\x17\x87\xd3\xc8\x7d\xda\x9b\x4c\xbe\x3c\xfb\x86\x61\x67\xf1\xff\x4e\xe3\xce\x2e\xcf\x77\x1b\xe2\xfc\xdd\xc7\xab\x9d\x46\x88\x0d\xc6\xa6\xf5\xdd\x7c\xd8\xd5\xc0\xd4\xec\xc7\x28\xb0\xfb\xe8\x67\xef\x77\xb6\xfe\xec\xfd\xf6\xe1\x63\x57\xdf\xe5\x81\x4d\xc3\x1f\xa7\xc6\x6e\x3a\x5c\xbd\x78\x75\xf0\xc7\x0e\xa3\x47\xf9\x34\xc2\xde\xe4\x53\xdc\x50\xb8\x42\xc1\x95\xc2\x6c\x47\x19\xae\x69\x17\x5c\x08\x70\x61\xa3\x76\x8f\x8e\x28\x44\x1c\x50\xf5\xef\x20\x35\xdc\x0f\x58\x71\xaf\x37\xe0\x46\x9a\x6a\x28\xfb\xc5\xa6\x28\xb8\x6b\x20\x10\x84\x04\xcd\x2b\xe9\x13\xd0\xb6\x4a\xc0\xde\x99\x0c\x6c\xa6\x62\x32\x15\xca\x8a\x05\x6b\x20\x44\x4f\x94\x5c\xd4\x2f\x27\x0d\x37\x16\x15\x80\x23\x34\x26\x19\x6b\x0c\x88\xa4\x91\x75\x2b\x56\x4b\x05\xcc\x73\xd3\x24\x29\x0f\x7c\x90\xa9\x5a\x47\x8a\x87\xa4\xfc\x62\x53\x06\x67\x95\x62\x5d\x2b\xd8\xc6\x3d\x2f\xc8\xa0\x46\x04\xb3\xaa\xca\x49\x77\xc7\x65\xc8\xa9\xed\x4c\xd6\x74\x09\x26\xd4\x25\x1c\x94\x86\x7b\x10\x4b\xc8\x51\xb2\x14\xee\x65\x56\x66\x8d\xb7\xc9\xf8\xba\x5f\x1c\x49\xbc\xe6\xd5\x52\x22\x1c\x1f\x8d\x08\x46\x39\xa5\xac\x20\x7e\xa9\xb9\xb1\x41\xd6\x2b\xa6\x79\x5a\x35\x75\xb6\x34\xea\x6c\x6d\xf4\x88\x0c\x9b\x2d\x96\xba\x58\x2d\x3d\xa6\xd2\x26\x79\xbb\x03\x44\xb7\x8a\x07\x8e\x2b\x23\x06\xa2\x81\x70\xcf\x43\x48\x9a\x28\x89\x25\x63\x45\x52\xdb\x12\x13\x3c\x68\xbb\x84\x5c\x18\xcb\xfe\x30\x10\xd5\x22\x20\xda\x44\x38\x22\x6a\x2c\x20\xad\xa7\xaa\x07\xdf\x9a\xcc\xcf\x1b\x82\x34\x68\x43\xda\xcc\x75\x1b\xf7\x0e\x99\xce\x06\x82\x70\x2d\x45\x77\x15\x41\x15\x98\x80\x25\x4e\x7d\x37\x10\xa0\x91\x55\x01\xd3\xbc\x44\xa2\xcd\xeb\xdb\xa2\x3e\x6f\x5e\xb6\xee\xd6\x22\x8e\x88\x4c\x46\x46\x93\x3c\x21\x1c\x80\x8f\xf1\x8f\x52\xf9\x30\xae\xf1\x8e\xc2\xbc\xb2\x80\x5e\x5a\x2f\xc3\x8a\x50\x9e\x9b\xca\x6a\x4a\x00\xe6\x03\xf4\x44\xa6\xa6\x07\x6c\x4b\x99\xd2\x19\x5e\x49\x2d\xe9\xdc\x30\x6f\x6f\x5a\x0c\x2c\xae\x48\x2a\xd7\x22\x6f\xa8\x7d\x98\xf5\x8c\x56\x2c\x0a\x07\x44\xca\xba\xac\xeb\x30\xf7\xc0\x2b\xc6\x3d\x70\x42\x87\xac\xa7\xe8\x5a\x5b\x57\x9c\x5a\x9f\x5b\x51\x9a\x90\xad\x7c\xb9\xde\xf5\xbc\xaa\xd8\x1d\x0f\x62\x5e\x56\x48\x93\xcc\xa5\xdc\xf3\x92\xf4\xba\xe8\xc0\x32\xc1\x8d\x00\x95\x08\x12\x60\xa5\x65\x15\x60\xf0\x76\x45\x98\xb8\xfa\x96\x74\x3d\x4b\x1b\xe7\x96\x91\x93\x6b\xcd\x20\x65\x22\x4a\xf1\x30\xe2\xf6\x86\x4c\x92\x74\xc3\x6e\x5c\x48\x35\x68\xa0\xb2\x78\xa5\x8a\x78\xa5\x4a\x47\x29\x69\x16\xb4\x9c\x36\x68\x9c\x79\x30\x14\xe5\x0d\x47\x0c\x53\x0a\x01\x52\x6f\x5b\x22\x54\x2e\x50\x86\x2b\x45\xc3\x95\xca\xc3\x95\xee\x83\xfd\x00\x41\xd7\x55\x71\x04\x6a\x69\x84\xf5\x09\x2e\x48\x8c\xef\x40\xea\x5c\x2f\x4c\x8a\xf8\x1d\x20\x75\x34\xe4\x76\xe0\x30\x43\x3c\xf9\x5a\x6b\xee\x68\x39\x09\x3a\x6f\x03\x39\xf8\xf5\x6d\x9c\x6c\x84\x40\xcd\xd5\xb7\xac\x5f\x63\x84\xb0\x2e\xb9\x5c\xdf\xb2\xb8\x0b\x2a\x0f\x02\x64\x3a\x46\x37\x34\x42\xca\x88\xf4\x2d\x6b\x0d\x9d\x4a\xed\x81\xea\x86\x0d\x59\xa3\x1a\x1b\xb2\xf2\x34\x36\x5e\x2c\x09\x42\xd2\x2d\x0d\xf9\xba\x35\x99\x67\x7a\x48\xbd\xd1\x1a\x32\xe6\x28\x31\x32\x70\xb7\x3e\x73\x86\x05\x63\xe0\x0e\x41\x11\x3f\x51\xf3\x63\x39\xc9\x3a\xde\xa6\xd9\x77\xd2\x65\xe5\xc1\xef\x31\x49\x19\xca\x19\xf0\xc4\x01\x2e\x86\x9f\xb4\xb4\x3a\xb8\xcc\x51\xea\xb1\x8f\x8c\x44\xba\xd7\x78\xb8\xeb\xb9\x3b\x2f\xe9\xa9\xd7\xe3\x65\x01\x87\xfe\x62\xef\xb4\xcc\xe7\x05\x41\x67\x71\x83\x93\x1b\x32\x55\x3d\x88\xac\x5c\xfb\x74\x36\x44\xac\x35\x36\x19\xa6\x50\x73\xd7\xa7\xa2\x8e\x37\x29\xd3\xdd\xb2\x67\x3d\xd0\x88\xde\x23\xaa\x50\x8f\x89\x81\x18\xb8\x0f\x6c\x7d\x39\x18\x68\x4d\x76\x63\xac\x96\x0d\xef\x2f\xeb\x19\xe7\xc0\x54\xd2\x34\x05\xe9\xad\xd0\x1c\x17\x39\x7b\xdb\x42\x0b\xd2\xd4\x36\xa7\x3d\x84\xd6\x17\xbd\x62\x8b\x8e\xec\x96\x9e\xec\x36\x11\x4d\x71\x7d\x60\xa1\xd9\xd6\x31\x8a\x39\x54\x71\x03\xf3\xba\x8e\x67\xc4\x6a\x5c\x41\xfc\x35\x90\x8e\x7b\xae\x47\x2c\xdb\x1c\xeb\x4c\xf3\xfb\xaf\xd5\x4a\x33\xaa\xed\x0a\xad\x82\x62\x2c\xef\xbb\xa6\xd2\x04\xf0\x4b\xae\xf2\x4a\xfc\x2b\xb5\x71\x9b\xda\xb8\x55\x6d\xfc\xcb\xa1\x57\x12\xd2\x6d\x00\x41\x08\xab\x5d\x82\x74\x6b\x23\x68\xb2\x05\x11\x34\x89\x41\x08\xda\x92\x66\xba\x9b\x1a\xca\x98\x8a\x96\xe3\xb2\x2d\x71\xda\x80\x91\xa1\x2b\xbf\xc3\x39\x0c\x69\x6a\x21\xd4\x34\x83\xda\xe0\x74\x62\x76\x4c\x5b\x48\xb4\x85\x44\xde\x43\xd9\x3e\xcf\x25\x71\x9c\x4b\x62\x99\x4b\x62\x9e\x38\xe2\x38\x19\xc4\x98\xc6\xe5\x22\x1e\xca\x81\xf3\xec\x10\xc7\xd9\x21\x96\xd9\x21\x8e\xb3\xc3\x8e\x2a\x45\x46\x12\x59\xfe\x88\xdb\xf3\x47\xcc\xd2\x45\x1c\xe5\x86\xb8\x3d\x37\xec\x68\x59\xc5\x5c\xce\x93\xe7\x02\xcc\x12\x42\x2c\x12\xc2\x32\xb7\xc0\xb9\x4e\x41\x0b\xe7\xd9\x5a\x9c\xeb\x8a\x56\xd1\x85\x39\x6f\x43\x45\xd2\xa9\x18\xb5\x54\xc0\xc0\xd3\x39\x88\xb2\x31\x5c\xa5\x3b\xf0\x06\x1f\x11\x22\x8f\x49\xd1\x6a\x32\x44\x87\x68\xa8\xec\x19\xc7\x53\xbc\x44\xa7\xa4\x48\x4b\x9e\x1c\xa1\x79\x92\x94\xdf\xe0\xca\x0b\x1c\xae\x34\x3d\x5c\xd6\x90\xf4\x45\x0e\xfb\x58\xde\xf2\x52\x11\x69\x32\xc0\x0a\xb3\x30\xb9\x42\x65\x87\x7d\x16\x60\x68\x15\x1a\x9a\xa0\xd2\x37\x94\x6e\xd1\x17\x69\x5c\xcf\x55\xa0\xa0\xe0\x46\x09\xdf\x86\x2d\x1e\x66\x36\x34\x6e\xa1\xa3\xac\x5d\x82\xf7\xad\x19\xf1\x63\xe1\x2d\x3d\x0c\xc6\x87\xcc\xa6\xe2\x36\x3c\xbe\x0c\xb7\xa3\x4b\x56\x4b\x8f\xb4\x96\x9e\xb1\x79\x2a\xd7\xa3\x34\x4d\x2d\x55\xa9\x03\x06\x8b\xda\x41\xc9\x25\x7d\x32\x58\xea\x7c\x1d\xc5\xb3\xef\x88\x82\xb4\x9b\x22\x22\x97\xd1\x2e\x87\xc9\xc0\xb2\x7f\x0c\xec\xa8\x29\x1f\xbf\xba\xcf\xde\xbf\xbf\xf8\x7d\xba\xae\xf6\x4d\xf7\x20\xb8\x96\x16\x56\x6b\x30\x21\x8a\xaf\x05\xa4\x11\xaa\xad\xba\x57\xc3\xcf\x5f\x7a\x0a\xee\x09\x95\x3f\x6a\x16\x0f\x8c\x0e\x3c\x5a\xc3\x55\x8c\x8d\xbb\xeb\xd4\xf5\xd1\xf5\xdb\xe9\x51\xc1\xfd\xf4\xf5\xfe\xc1\xb3\x35\xb1\xe4\xaa\x85\x11\x71\x7d\x67\x29\x67\xdd\x30\x4a\xfc\x3b\xfb\x47\xa7\xc6\xe4\x0b\x51\xe6\x7f\xd0\xe4\x93\x5f\xcf\xe4\xe7\x2f\x9e\x1f\xfc\x76\xf8\x6b\xda\x7d\xf2\x0b\x2e\xf1\xa3\xc3\x57\x47\xaf\x8e\x7f\x3b\x7c\xf5\xf2\xbf\xcb\xf6\xe2\xec\x3d\xfc\x59\xa1\xb6\x1f\x8d\x7b\x31\x27\xa3\xc7\x7b\xb3\x38\x3e\x52\xd0\x9b\xf9\x29\xfe\xdf\xd9\x02\xee\x35\xdb\xf6\x3a\x1f\xf9\xaf\x64\x16\x99\xd1\x6b\xfe\xc6\x03\x5f\x38\x2b\x0d\xf9\xc8\x23\xe6\x50\xab\x16\xe7\x59\x82\xa8\xf0\x91\xfd\x94\x3e\x4e\x75\xe5\xf5\x17\xb8\xef\xf6\x98\x98\xb3\xfe\x91\xe2\x91\xad\xd0\xe9\x25\x64\x32\xbd\x5f\x7f\xcb\xfc\x4e\x2b\xb4\xad\x64\xbd\x62\xaa\x0a\x4f\x6e\xc5\x50\x3e\x39\x7e\x88\x45\xf8\xe2\xd5\x01\x73\x42\x32\xad\xa5\x65\xf4\xf1\x26\xaf\xc9\x32\xa4\xae\xca\xb7\x26\xa6\x62\x4c\x1a\x0c\xfe\x91\xdd\x11\x15\x18\x3c\x10\xc1\xfd\x43\x7c\x60\x1d\x18\x76\xb3\x62\x73\x6e\x2a\x05\x8c\xff\xe4\xc9\x15\xdc\x51\x5b\x4e\x67\x1f\xd9\x9b\xd9\x29\xbb\x3c\x9b\xbd\x61\x57\x67\xb3\xcb\xd3\xb7\x0f\x31\xe6\xc6\xd5\x43\x20\x51\xd6\x8c\xbf\x13\xd2\x0f\x03\xca\xda\x45\xeb\x58\x25\xac\x5d\xc8\xf4\x00\x6b\xdb\x14\x8d\x62\xf7\x2c\x58\xe2\x9c\x14\x94\x2a\xab\xb9\x34\x34\xb3\x47\x08\x73\x8b\x21\x4b\xf6\xb3\xee\x7a\x74\x98\x72\x7f\x9c\x73\x0f\x8f\xee\xf0\xab\x3f\xaf\xd8\xec\xcd\xf9\xbb\x0f\x0f\x71\x75\xef\xdf\x9f\x75\x7a\x1f\x1e\x9c\x1c\xbc\x3c\x78\x79\xf2\xf2\x78\x87\xd3\xfb\x7c\x76\xf5\xf7\xb3\x37\x3f\xe6\x10\xff\x66\xe7\x3d\xfb\xae\x5d\xfa\x78\xae\x7d\xfe\x88\xae\x8d\x66\xee\x77\x2f\x8c\x10\xc0\xef\x5b\x5f\x81\x97\xa6\xd9\xaf\xad\xdf\xef\x8c\xda\x97\xb8\x5f\xc9\xba\x06\x0f\x9b\x5d\xf1\x33\x22\xde\x6e\x2b\xff\xab\x73\xe1\xe1\xc6\xda\xc7\x8f\x89\x51\xd1\xff\xbb\xb8\xb8\x7e\xd0\x0e\x9d\xfb\xa7\x52\xfd\xf4\xed\xe5\x03\x95\xef\x5f\x88\x98\xb6\x55\x9b\x9e\x83\x63\xf4\x2e\xa8\x7a\x0b\x77\xdb\x82\x5f\x6d\xb8\xa7\x30\xff\xfc\xe2\xcd\x3f\xdf\x9f\x3d\x28\x63\x14\xe2\x69\x66\xee\xe3\xec\xf4\xf4\x41\x13\xb7\x10\xe9\x1b\x81\xf3\x56\x00\x22\x5b\x6a\x56\x7c\x85\x1b\xf8\xe2\x7b\x5a\xf0\x5c\x3c\xcd\x9c\x7d\xbc\xbe\x9c\x9d\x3e\x68\xce\xa4\x75\xe4\x97\x02\x0e\xbc\x7e\x12\x43\x2e\x67\xbf\xbf\xbb\x78\x50\x56\xbc\xe5\xf7\x19\x38\xfe\x6d\xdc\xe6\xf9\xf4\x29\x6c\xbc\x7e\x77\xfe\xa0\xa9\x5a\xce\xb9\x69\x5a\xf7\x34\xba\x5f\xff\xc9\x4e\x2f\x3e\xfc\xff\xbb\xbf\x7d\x83\x05\x7b\x93\x4f\x7b\x5f\xf6\xf6\xfe\x13\x00\x00\xff\xff\xf1\x77\x31\xfd\x05\x2d\x00\x00")

func nestedContainerJsonBytes() ([]byte, error) {
	return bindataRead(
		_nestedContainerJson,
		"nested-container.json",
	)
}

func nestedContainerJson() (*asset, error) {
	bytes, err := nestedContainerJsonBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "nested-container.json", size: 11525, mode: os.FileMode(420), modTime: time.Unix(1525732804, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _fuseContainerJson = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xec\x9a\x5b\x53\x1b\x3b\xf2\xc0\xdf\xf3\x29\x5c\x7e\xce\x03\x01\xc2\x81\xbc\xf9\x6f\xf8\x6f\xa8\x85\xc0\x02\x5b\xe7\x9c\xda\x4a\xa9\x84\xa6\x67\xac\xb5\x6e\xa8\x35\x06\x57\x2a\xdf\x7d\x4b\x33\xf8\xa2\x96\x7c\xce\x81\x38\x29\x6f\x6d\x1e\x42\xac\x5f\xb7\x2e\xdd\xa3\x4b\xb7\x66\xbe\xbc\x19\x0c\x86\x15\xd4\xbc\x55\x61\x24\x82\xb4\x66\xf8\x61\x30\xbc\x1d\x5f\x5e\xb3\xd1\xf8\x8e\x9d\xdd\xdc\x7c\xba\x1a\xbe\x8d\x4a\xdc\x8b\xc9\x25\x77\xc3\x0f\x83\x7f\xbd\x19\x0c\x06\x83\x2f\xdd\xdf\x67\x81\x0c\x20\x42\xeb\x61\x55\xf9\x66\xfc\x91\xfd\x76\x7c\xc4\x8e\x0e\xbb\xea\x9d\x26\xb6\xf7\xa3\x35\x65\x5c\xb6\xd5\x49\x93\x7a\xcb\x4a\xa9\xe0\x60\x7f\xf8\xcc\x3f\x77\xff\x7f\x7d\xfb\x57\xc7\x32\x8a\x7f\x5f\x33\x98\xd1\xcd\xe5\x6b\xfb\xbc\x3c\xbf\xbe\x7d\x4d\x97\xb1\x5e\xd9\x01\x7d\x8b\x9f\x5e\xef\x86\x55\x03\x5b\x1f\xd5\xb7\x0c\xe9\xec\xe2\xb5\x7e\x3a\xbb\xd8\x3c\xa6\xd8\xea\x37\xfa\x6a\xd1\xc4\x77\x19\xdb\x6b\x07\x76\x7b\x70\xb2\xf7\xdb\xcb\x87\x14\xab\x91\x2e\xdf\x0c\x06\x9f\xbb\xd5\x8d\x73\x14\x5c\x29\xcc\x97\xb7\xe1\x9a\x36\xc9\x85\x00\x17\xd6\x6d\xeb\xc9\x21\x45\x88\x09\xa9\xfe\x1d\xa4\x86\xa7\x84\x29\xee\xf5\x3a\xb8\x97\xa6\x4a\xca\x7e\xba\x5e\x14\xdc\x35\x10\x08\x41\x42\x26\x95\xf4\x29\xd0\xb6\x4a\x81\x7d\x34\x19\x58\x7b\xcc\x11\x29\x2b\xa6\xac\x81\x10\x3d\x5a\xe2\xd1\x96\x5c\x60\xb8\xb1\xa8\x00\x1c\x11\x61\xaa\x6b\x8d\x01\x91\x8e\xda\xba\x39\xab\xa5\x02\xe6\xb9\x69\x52\x6d\x0f\x3c\xd1\xad\x5a\x47\x8a\xfb\xa4\x7c\xb0\x5e\x06\x67\x95\x62\x5d\x2b\xb0\x89\xbf\x2b\x08\x82\x2a\x42\x66\x55\x95\x0b\xdc\x23\x97\x21\xc7\x9b\x69\xd6\xcc\x0c\x4c\xa8\x4b\x28\x31\x0e\x9e\x40\xcc\x20\x27\xa9\x87\xe0\x49\x66\x65\xd6\x78\x9b\x3a\xae\xee\x27\x69\x5a\xb5\xe6\xd5\x4c\x22\x1c\x1d\x16\x21\xa3\x5c\x29\x2b\x88\x5f\x6b\x6e\x6c\x90\xf5\x9c\x69\x9e\xce\xde\x3a\x9b\x9a\x75\x36\x37\x7b\x42\x86\x94\x4d\xd8\xba\x30\x63\x7b\x46\x6b\x9a\xf4\x29\x76\x80\xd8\x50\xf1\xc0\x71\x6e\x44\x02\x1b\x08\x4f\x3c\x84\x74\xb4\x4a\x62\x89\x5a\x91\x9a\x69\x89\xd9\x1e\xb4\x9d\x41\x5e\x11\x4b\x7d\x60\x20\x26\x44\x40\x46\x1c\x51\x11\xd6\x58\x40\x54\x8f\x9a\x1a\x7c\x6b\xb2\x67\xb8\x80\xa4\x72\x1b\xd2\x0d\xac\x6e\xe3\x3e\x40\xa6\x50\x03\x41\xb8\x96\x92\xc7\x8a\x90\x0a\x4c\xc0\x12\x4b\xfb\x6c\x20\x40\x23\x69\xe5\x88\xd2\xe7\x1f\x61\x9b\xeb\xb5\x05\xbd\xbc\xb9\x52\x6b\xdd\x7a\xa1\x03\xec\x61\xa6\x2b\xa3\x1b\x3c\x81\x0e\xc0\xc7\xf3\x83\xe2\xbc\x7b\xd7\x78\x47\x51\xae\x54\x40\x5e\x5a\x2f\xc3\x9c\x60\xcf\x4d\x65\x35\x85\x80\x79\xc7\x3d\xcc\xcc\xf1\x80\xb9\x2b\x7b\x98\xeb\x2a\xa9\x25\x7d\xfe\xcc\xdb\xfb\x16\x03\x8b\x2b\x86\xea\xb7\xc8\x1b\xea\x13\xcc\x7a\x43\x2b\xa6\x05\xe7\x45\x6c\x5d\xd6\x5d\x98\x78\xe0\x15\xe3\x1e\x38\x11\x85\xac\xe5\xf8\xa8\x6c\x5d\x71\xea\xb5\xdc\xe2\x92\xb9\xd9\x8a\x95\xcf\xbb\x1d\xaf\x2a\xf6\xc8\x83\x98\x94\x84\xd2\xa4\x2e\x5a\xe7\xef\x4a\x02\xaf\x0b\x8d\x59\x26\xb8\x11\xa0\x52\x48\x0e\x2a\x69\x59\x05\x18\xbc\x9d\x13\x1a\x57\xc3\x8c\xae\x39\x69\xe3\x1c\x62\x24\xaa\x78\xa6\x48\x69\x24\xe9\x19\x12\x59\x7b\x4f\x26\x80\x74\xc9\x0e\x33\x95\x2a\x19\xa1\xca\xf6\x73\x55\xd8\xcf\x55\xc9\xd9\x4a\x9a\x29\x2d\xa7\x9b\x4f\x9c\x71\x60\x28\xc9\x1b\x2a\x52\xa6\x14\x02\xa4\x3d\x6c\xd8\xbd\x73\xc5\xd2\x76\xae\xe8\x76\xae\xf2\xed\x5c\xf7\x87\x6b\x82\x40\xd7\x55\x21\x64\xd1\xd2\x08\xeb\x53\x34\x25\x67\x6a\x07\xd2\x4e\xf5\xd4\xa4\xa7\x6c\x07\x88\x0e\x3d\xc6\x3a\xb0\x9f\x11\x9e\x3e\x4b\xad\xb9\xa3\xe5\xb4\x92\xf3\x36\x90\x60\x4f\x3f\xc4\x09\x87\x10\xa8\xbb\xf4\x03\xeb\xe7\x3f\x81\xd6\xa5\x8f\x54\x3f\xb0\xb8\x8a\x2b\x0f\x02\x64\x1a\x0e\x2d\x44\x08\x69\x24\xad\x1f\x58\x6b\xe8\xf4\xd1\x1e\xe8\xf8\xb1\x21\xeb\x49\x63\x43\x56\x87\xc6\xc6\x8b\x19\x21\x48\xba\xa3\xc7\xac\x6e\x4d\xe6\xe1\x1e\x51\x8f\xb6\x86\x8c\xa9\x18\x54\x1b\x78\x7c\x8e\x03\x92\x09\x6c\xe0\x11\x41\x11\x7f\x53\xf7\xc5\x72\x5a\xcf\xf1\x36\x9d\x81\x4e\xba\xac\x9c\x3c\xd7\x18\xc8\x26\xe5\x0c\x78\xe2\x48\x17\xb7\xe8\x74\xea\x77\x68\x96\x93\xb4\xa7\xfe\x84\x21\x35\x7b\x2b\x93\x9b\x12\xf7\xe8\x25\x8d\x58\x7a\x36\x2b\xa0\xa4\x8f\xd8\x2b\x2d\xf3\x49\x01\xd2\x19\xb4\x60\xa9\x3b\x33\xb3\x3c\x88\xac\x5c\xfb\xf4\x8c\x8e\x4c\x6b\x6c\x32\x46\x91\xe6\xae\x4f\x95\x1c\x6f\xd2\xec\x6c\xc3\x5e\xe5\x81\x9e\xa4\x3d\xa1\x83\xee\x19\x71\x0c\x06\xee\x03\x7b\xce\x90\x13\x91\x26\x3b\x4f\x54\x93\x0d\xef\xef\xd1\x32\xee\xc0\x54\xd2\x34\x05\x81\xb7\x42\x73\x9c\xe6\x92\x87\x16\x5a\x90\xa6\xb6\xb9\xc8\x43\x68\x7d\xa1\x17\x6c\xd1\x91\x95\xdf\x0b\xba\x4d\x81\xa6\x63\x3e\xb0\xd0\x6c\xea\x08\xc5\x04\xaa\xb8\x51\xf1\xba\x8e\xe7\xf4\xbc\x2c\x24\xbe\x5e\x0a\x1c\xf7\x5c\x17\x25\x6c\x11\xb6\x31\xcd\x9f\xfe\x4c\x43\x9a\xa2\x46\xf7\xa3\x55\x50\xe8\xdb\xfb\xae\x09\x69\x02\xf8\x19\x57\xb9\x02\xfe\x91\x49\x85\x5d\x79\x29\xd8\x60\x12\xfe\xe1\x70\xe6\x12\xd2\x4c\x17\x41\x08\xab\x5d\x8a\xe8\x96\x85\xa0\xc9\xf6\x81\xa0\xc9\x3e\x8c\xa0\x2d\x69\x46\x77\x8f\x99\x52\x53\xd1\x72\x5c\x3e\x25\x96\x6e\x1e\x91\xd2\x15\xd9\xb1\x1c\x85\x74\xea\x40\xa8\x69\xb4\xbd\x60\x69\x94\xd3\xd1\xb6\xa0\x99\xc5\x9e\x98\xe5\x2d\x58\xc8\x5b\xb0\x94\xb7\x60\x39\x6f\xc1\x52\xde\x82\x79\x82\x82\xe5\x44\x03\x63\x4a\x90\xab\xfa\x3c\x35\xc3\x52\xf6\x81\xe5\xec\x03\x4b\xd9\x07\x96\xb3\x8f\x0e\x97\x54\x8b\x9a\x59\x9e\x82\x9b\xf3\x14\xcc\x52\x12\x2c\xe6\x1e\xb8\x39\xf7\xe8\x44\xb2\x8a\x79\x81\x27\x57\x81\x98\x25\x1b\x58\x48\x36\x4a\xf1\x24\x4e\x74\xba\x69\xe3\x24\x5b\x27\x13\x5d\x51\x15\xba\x70\x26\x6d\xa8\x48\x08\x1e\x77\x6e\x15\x30\xf0\x34\x46\x41\xd9\x18\xae\xd2\x7b\xa9\x05\x3b\x24\x30\xdf\x93\xa3\xc7\x48\xd7\x1d\xa1\x47\x49\x4f\x1d\x4f\xcf\x13\x74\x4a\x8a\x74\x99\x92\x70\x27\x0f\xa6\xf3\x5b\x90\xd2\x25\x08\xce\x35\x3d\xc8\x9f\x11\x69\x9f\x04\x71\xb1\xbc\xe1\x96\x32\x8a\x48\xc7\x73\xcc\x8e\x94\x39\x2a\x9b\xec\x1d\x01\x92\x56\x42\x43\x93\x25\x7a\xcf\xda\x2d\xd8\x42\x6a\xd0\xf3\x0a\x14\x14\x78\x31\x99\x58\x48\x0a\x97\xb9\x0b\x11\x6e\x10\xc5\x3a\x76\x06\xde\xb7\xa6\x28\x2b\x57\xda\xd0\x5a\xe2\xb4\x90\xd9\x5f\xb8\x9d\x2a\x5f\x4e\xb5\xc5\xcb\x88\x96\x86\x16\x2d\x8d\x85\xf2\xb4\xa0\x27\xe9\x54\x68\xe9\xd0\x3b\x60\xb0\xa0\x95\x18\x34\xa3\xd7\x81\x33\x9d\xcf\xeb\x18\x97\x1c\x52\x90\xee\x10\x91\x90\x0b\xa0\x2e\x8e\xcd\xc0\x6c\xf9\x92\x63\x21\x19\xf2\xfc\xd5\xe6\xe8\xe2\xe2\xea\xd7\xe1\x4a\xc3\x37\xdd\x5b\x8e\x55\x1d\x61\xb5\x06\x13\x62\xa5\x95\x9a\x34\x42\xb5\x55\xf7\x42\xe4\xcb\xd7\x25\x85\xa7\x35\xda\x41\xfa\x32\xa7\xf0\x16\x45\x28\x6b\xe0\x5b\x86\xba\x6c\xea\xcb\xf2\x57\x37\xc2\x0a\x9e\x86\x1f\x06\x7b\x6f\xd7\xe9\x8c\xab\x16\x86\x1f\x06\xfb\x7b\xc7\x7b\xef\xf7\xde\x1f\xbf\x3f\xca\xc5\x77\x8f\x36\xab\x67\xdd\x72\x24\xf1\xdf\xe5\xe8\xf6\xef\x67\xa7\xec\xec\x1f\xc3\xa5\xd2\xd7\xcc\x82\xef\xed\x38\x07\x1e\xad\xe1\x2a\x9e\xc6\x3f\xd8\x7d\x05\xfa\x17\xbc\xf6\x3f\xeb\xae\xe3\x9f\xee\x7a\x89\xbb\xde\x1d\xbc\xdb\xfb\x65\xff\xa7\xcf\x5e\xea\xb3\xe3\x9f\xcb\xf2\x45\x3e\x3b\xdc\x3f\x39\x3c\x39\xfa\x65\xff\xe4\xfd\x7f\xa1\xdf\x48\x04\xba\xff\x83\x0e\xfb\xd5\x00\xb8\x17\x13\x32\xa8\xee\xf6\x4f\x1c\x1d\x2a\x58\x79\xe6\xf3\xf3\xaf\x6f\x34\x97\x7b\xcd\x36\xbd\x7c\x8e\xb2\x3f\x09\xc8\x13\x4f\xad\xc9\xee\x3d\xf0\xa9\xb3\xd2\x90\x6f\x29\xc4\x04\x6a\xd5\xe2\x24\xcb\xe3\x14\xee\x88\xa3\xd3\xef\x45\x7a\xb0\xfa\x94\x66\x8b\x7e\x17\x13\xd6\xdf\xe0\xee\x88\xdd\x3a\xbd\x3a\x1e\x0c\x86\x4f\xab\x6f\x9b\xb6\x66\xb7\xb6\x95\xac\xe7\x4c\x55\x61\xb7\xed\x4e\xc1\xf1\xd1\xd6\x1d\x81\x07\x27\x7b\xcc\x09\xc9\xb4\x96\x96\xd1\xeb\xf1\x54\x9a\xe5\x21\x9d\xd8\xb7\x26\x26\x43\x4c\x1a\x0c\x7e\x47\xbc\x19\x07\x96\xfa\x2e\x92\xa7\xad\x7b\xcf\x3a\x30\xec\x7e\xce\x26\xdc\x54\x0a\x18\xff\xf1\xb3\x49\x70\x97\x59\x3f\x1e\x5d\xb3\xd3\xd1\x98\xdd\x9c\x8d\x4e\xd9\xed\xd9\xe8\x66\xfc\xf1\x3b\x2c\xa0\xd6\x90\xfc\xbb\x4c\x7e\xfc\xc9\xb5\xc9\x25\xb7\xbf\xdf\xb2\xd1\xe9\xe5\xf9\xa7\xad\x3b\xc3\xc3\xbd\xb5\xbb\xf3\xec\xa3\xa1\xff\x77\x75\x75\xb7\x75\x3b\xc5\xc4\xef\x9a\x9d\xe3\x8f\x37\xdf\xc3\xd2\xfe\x7e\x8d\x69\x5b\xb5\xe9\x0b\x04\x69\x64\x28\xe0\x7a\x03\x7f\x68\xc1\xcf\x17\x7c\x97\xfc\x76\x79\x75\xfa\xcf\x8b\xb3\xed\xc7\x13\x42\xec\xd6\xfc\xb8\x1e\x8d\xc7\xdb\x9f\x1e\x53\x91\xbe\xd7\x72\xde\x0a\x40\x64\x33\xcd\x0a\x6f\xba\x97\xb2\xc2\x3b\xea\xe0\xb9\xd8\xad\x99\x71\x7d\x77\x33\x1a\x6f\x7f\x66\x48\xeb\xc8\xe7\x4b\x0e\xbc\xde\x29\xcb\x6f\x46\xbf\x9e\x5f\x6d\x3f\xc2\xda\xf0\x25\x1a\x96\xbf\xac\x5e\x5c\x9e\xef\x92\x63\xee\xce\x2f\xb7\x3f\x21\x66\x13\x6e\x9a\xd6\xed\x96\xa1\x77\xbf\xb3\xf1\xd5\xa7\xff\x3f\xff\xdb\x0b\xcd\x7d\x13\xf5\xbe\xfe\x27\x00\x00\xff\xff\x03\x9e\x72\x97\x67\x34\x00\x00")

func fuseContainerJsonBytes() ([]byte, error) {
	return bindataRead(
		_fuseContainerJson,
		"fuse-container.json",
	)
}

func fuseContainerJson() (*asset, error) {
	bytes, err := fuseContainerJsonBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "fuse-container.json", size: 13415, mode: os.FileMode(420), modTime: time.Unix(1534401730, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"default.json":          defaultJson,
	"nested-container.json": nestedContainerJson,
	"fuse-container.json":   fuseContainerJson,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}

var _bintree = &bintree{nil, map[string]*bintree{
	"default.json":          &bintree{defaultJson, map[string]*bintree{}},
	"fuse-container.json":   &bintree{fuseContainerJson, map[string]*bintree{}},
	"nested-container.json": &bintree{nestedContainerJson, map[string]*bintree{}},
}}

// RestoreAsset restores an asset under the given directory
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	err = os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
	if err != nil {
		return err
	}
	return nil
}

// RestoreAssets restores an asset under the given directory recursively
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}
