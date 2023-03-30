import http from 'http';

const server = http.createServer();

server.listen('5959', () => {
    console.log('service run: http://127.0.0.1:5959');
});

server.on('request', (req, res) => {
    try {
        // 跨域允许携带凭据（cookie之类）
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        // 要允许跨域携带cookie，必须设置为具体的域，不能是‘*’
        res.setHeader('Access-Control-Allow-Origin', 'http://127.0.0.1:5959');
        res.setHeader('Content-Type', 'application/json');

        const url = req.url?.split('?')[0];
        if (url === '/') {
            res.statusCode = 200;
            res.end(JSON.stringify({ text: 'hello world' }));
        } else if (url === '/login') {
            res.setHeader('Set-Cookie', 'name=wst;age=24;Max-Age=666;');
            res.statusCode = 200;

            // 返回json格式数据到客户端
            res.end(JSON.stringify({ text: '登录成功' }));
        } else if (url === '/test') {
            res.statusCode = 200;
            res.end(JSON.stringify({ text: '通过测试' }));
        }
        console.log(url);
        // res.end('service run');
    } catch (err) {
        console.error((err as Error).message);
        res.statusCode = 500;
        res.end('service error');
    }
});

server.on('error', err => {
    console.log(err);
});
