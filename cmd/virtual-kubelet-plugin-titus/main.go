package main

import (
	"context"
	"github.com/Netflix/titus-executor/vk"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := vk.NewVk()
	if err != nil {
		panic(err)
	}

	err = p.Start(ctx)
	if err != nil {
		panic(err)
	}
}
