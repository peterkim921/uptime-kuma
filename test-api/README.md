# 测试 API 服务器

这是一个简单的状态切换 API 服务器。

## 安装依赖

```bash
npm install
```

## 运行服务器

```bash
npm start
```

服务器默认运行在 `http://localhost:3002`

## API 端点

### GET /flip
切换状态（on/off）

每次调用都会切换当前状态。

## 使用示例

```bash
# 切换状态
curl http://localhost:3002/flip

# 响应示例
# {"status":"on","state":true}
# 或
# {"status":"off","state":false}
```

