package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"

	"github.com/JUXON-AI/jxpkg/apis/apiobj"
	"github.com/JUXON-AI/jxpkg/apis/constants"
	"github.com/JUXON-AI/jxpkg/apis/errcode"
	grt "github.com/JUXON-AI/jxpkg/apis/runtime"
	"github.com/JUXON-AI/jxpkg/config"
	"github.com/JUXON-AI/jxpkg/logs"
	"github.com/gin-gonic/gin"
)

const maxRequestBodyBytes int64 = 1 << 20

type apiOptions struct {
	maxRequestBodyBytes int64
}

// APIOption 配置 API handler。
type APIOption func(*apiOptions)

// WithMaxRequestBodyBytes 设置单个 API 的请求体上限。
func WithMaxRequestBodyBytes(size int64) APIOption {
	return func(options *apiOptions) {
		if size > 0 {
			options.maxRequestBodyBytes = size
		}
	}
}

// API 将反射式 API handler 转换为支持独立配置的 Gin handler。
func API(hdr interface{}, opts ...APIOption) gin.HandlerFunc {
	return transAPI(hdr, opts...)
}

func transAPI(hdr interface{}, opts ...APIOption) gin.HandlerFunc {
	options := apiOptions{maxRequestBodyBytes: maxRequestBodyBytes}
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}
	return func(ctx *gin.Context) {
		hdrType := reflect.TypeOf(hdr)
		switch hdrType.Kind() {
		case reflect.Func:
			if hdrType.NumIn() != 3 {
				logs.Error("invalid handler params number.", hdrType.NumIn())
				grt.InternalError(ctx, fmt.Sprintf("invalid handler params number. %T %v", hdr, hdrType.NumIn()))
				return
			}
			if hdrType.NumOut() > 1 {
				logs.Error("invalid handler returns number.")
				grt.InternalError(ctx, fmt.Sprintf("invalid handler returns number. %T %v", hdr, hdrType.NumOut()))
				return
			}

			inVal := reflect.New(hdrType.In(1).Elem())
			outVal := reflect.New(hdrType.In(2).Elem())
			{
				in := inVal.Interface()
				ctx.Request.Body = http.MaxBytesReader(ctx.Writer, ctx.Request.Body, options.maxRequestBodyBytes)
				err := json.NewDecoder(ctx.Request.Body).Decode(in)
				if err != nil {
					logs.Errorf("decode request failed, %s", err)
					grt.BadRequest(ctx, fmt.Sprintf("decode request failed, %s", err))
					return
				}
			}

			vals := reflect.ValueOf(hdr).Call([]reflect.Value{
				reflect.ValueOf(ctx),
				inVal,
				outVal,
			})
			if len(vals) > 0 {
				retVal := vals[0].Interface()
				if retVal != nil {
					err, ok := retVal.(error)
					if !ok {
						logs.Errorf("invalid handler returns type: %T", retVal)
						grt.InternalError(ctx, fmt.Sprintf("invalid handler returns type: %T", retVal))
						return
					}
					if err != nil {
						logs.Errorf("handler return error: %s", err)
						grt.InternalError(ctx, fmt.Sprintf("handler return error %T %s", retVal, err))
						return
					}
				}
			}

			if ctx.IsAborted() {
				return
			}

			fixBaseResponse(ctx, outVal)
			out := outVal.Interface()
			ctx.JSON(http.StatusOK, out)

		default:
			logs.Error("failed hdrType")
			grt.BadRequest(ctx, fmt.Sprintf("failed hdrType %T", hdr))
			return
		}
	}
}

func transHttp(hdr http.HandlerFunc) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		hdr(ctx.Writer, ctx.Request)
	}
}

func transHttpHdr(hdr http.Handler) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		hdr.ServeHTTP(ctx.Writer, ctx.Request)
	}
}

func fixBaseResponse(ctx *gin.Context, outVal reflect.Value) {
	_ = outVal.Interface()
	outType := outVal.Type().Elem()

	if field, ok := outType.FieldByName("Code"); ok {
		if field.Type.Kind() == reflect.Uint || field.Type.Kind() == reflect.Uint32 {
			codeVal := outVal.Elem().FieldByName("Code").Uint()
			ctx.Set(constants.CtxKeyCode, int(codeVal))
		} else if field.Type.Kind() == reflect.Int || field.Type.Kind() == reflect.Int32 {
			codeVal := outVal.Elem().FieldByName("Code").Int()
			ctx.Set(constants.CtxKeyCode, int(codeVal))
		}
	}

	for i := 0; i < outType.NumField(); i++ {
		f := outType.Field(i)
		if f.Anonymous && f.Type == reflect.TypeOf(apiobj.BaseResponse{}) {
			baseResp := outVal.Elem().Field(i)
			code := ctx.GetInt(constants.CtxKeyCode)
			if code > 0 && baseResp.FieldByName("Message").String() == "" {
				msg := errcode.GetMessage(uint32(code))
				baseResp.FieldByName("Message").SetString(msg)
			}
			baseResp.FieldByName("Env").SetString(config.Conf().MainConf.Env)
			baseResp.FieldByName("RequestID").SetString(ctx.GetString(constants.CtxKeyRequestID))
		}
	}
}
