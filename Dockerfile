# 第一阶段：构建
FROM golang:1.22-alpine AS builder

WORKDIR /app

# 复制依赖定义（尽管我们只用标准库，这是好习惯）
COPY go.mod ./
# COPY go.sum ./ 

# 复制源码
COPY main.go main.go

# 编译：CGO_ENABLED=0 确保静态链接，-ldflags="-s -w" 去除调试信息减小体积
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o netcut main.go

# 第二阶段：运行
FROM alpine:latest

WORKDIR /app

# 安装 ca-certificates 只是为了保险，Alpine非常小
RUN apk --no-cache add ca-certificates tzdata

# 从构建阶段复制二进制文件
COPY --from=builder /app/netcut .

# 暴露端口
EXPOSE 8080

# 创建数据卷挂载点
VOLUME ["/app/data"]

# 启动
CMD ["./netcut"]