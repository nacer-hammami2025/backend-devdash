const net = require('net');

async function findAvailablePort(startPort) {
  const server = net.createServer();

  return new Promise((resolve, reject) => {
    const tryPort = (port) => {
      server.once('error', (err) => {
        if (err.code === 'EADDRINUSE') {
          tryPort(port + 1);
        } else {
          reject(err);
        }
      });

      server.once('listening', () => {
        server.close(() => resolve(port));
      });

      server.listen(port);
    };

    tryPort(startPort);
  });
}

function createServer(app, initialPort = 3000) {
  return new Promise(async (resolve, reject) => {
    try {
      const port = await findAvailablePort(initialPort);
      const server = app.listen(port, () => {
        console.log(`🚀 Server running on http://localhost:${port}`);
        resolve({ server, port });
      });

      server.on('error', (error) => {
        if (error.code === 'EADDRINUSE') {
          console.log(`Port ${port} is in use, trying another port...`);
          server.close();
          createServer(app, port + 1).then(resolve).catch(reject);
        } else {
          reject(error);
        }
      });
    } catch (error) {
      reject(error);
    }
  });
}

module.exports = {
  findAvailablePort,
  createServer
};
