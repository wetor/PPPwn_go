package main

import (
	"encoding/binary"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

func Test_p64(t *testing.T) {
	type args struct {
		val int64
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		// TODO: Add test cases.
		{
			name: "-1",
			args: args{
				val: -1,
			},
			want: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		},
		{
			name: "-2",
			args: args{
				val: -2,
			},
			want: []byte{0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		},
		{
			name: "2",
			args: args{
				val: 2,
			},
			want: []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := p64(uint64(tt.args.val)); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("p64() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_str2mac(t *testing.T) {
	type args struct {
		val []byte
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
		{
			name: "0x100+0x7",
			args: args{
				val: toBytes(0x100+0x7, 6, binary.LittleEndian),
			},
			want: "07:01:00:00:00:00",
		},
		{
			name: "0x200+0xffffffff822c53cd",
			args: args{
				val: toBytes(0x200+0xffffffff822c53cd, 6, binary.LittleEndian),
			},
			want: "cd:55:2c:82:ff:ff",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, str2mac(tt.args.val), "str2mac(%v)", tt.args.val)
		})
	}
}
