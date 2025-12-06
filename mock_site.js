
const http = require('http');

let isUp = true;
const PORT = 54321;

const server = http.createServer((req, res) => {
    // Control APIs
    if (req.url === '/api/up') {
        isUp = true;
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('Site is now UP');
        console.log('Command received: Site is now UP');
        return;
    }

    if (req.url === '/api/down') {
        isUp = false;
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('Site is now DOWN');
        console.log('Command received: Site is now DOWN');
        return;
    }

    // The simulated website response
    if (isUp) {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('Hello! I am online.');
    } else {
        // Simulate offline by returning 503 Service Unavailable
        res.writeHead(503, { 'Content-Type': 'text/plain' });
        res.end('Service Unavailable');
    }
});

server.listen(PORT, () => {
    console.log(`Mock site running on http://localhost:${PORT}`);
    console.log(`Control APIs:`);
    console.log(`  Turn ON:  curl http://localhost:${PORT}/api/up`);
    console.log(`  Turn OFF: curl http://localhost:${PORT}/api/down`);
});
