package core

import (
	"errors"
	"reflect"
)

func FuncCall(m map[string]interface{},name string,params ...interface{})(err error){
	// 先判断一下这个函数是否存在
	if _ ,exist := m[name];!exist{
		var err = errors.New("func is not exist")
		return err
	}

	var fun = reflect.ValueOf(m[name])
	if len(params) != fun.Type().NumIn(){
		var err = errors.New("func need params is different")
		return err
	}
	// 创建一个切片存放参数
	var paramin = make([]reflect.Value,len(params))
	for key,value := range params{
		paramin[key] = reflect.ValueOf(value)
	}
	_ = fun.Call(paramin)
	//fmt.Println(result)
	return nil
}
