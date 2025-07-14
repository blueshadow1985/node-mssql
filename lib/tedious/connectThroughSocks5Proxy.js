const net = require('net');
const { Buffer } = require('buffer');

function createInitialRequest() {
  return Buffer.from([0x05, 0x01, 0x80]); // Version 5, 1 method, 0x80 = JWT auth
}

function createAuthenticationRequest(jwt, sccLocationId = '') {
  const jwtBuffer = Buffer.from(jwt);
  const locationBuffer = Buffer.from(sccLocationId);

  const authBuffer = Buffer.alloc(1 + 4 + jwtBuffer.length + 1 + locationBuffer.length);
  let offset = 0;

  authBuffer.writeUInt8(0x01, offset++); // Custom auth version
  authBuffer.writeUInt32BE(jwtBuffer.length, offset); offset += 4;
  jwtBuffer.copy(authBuffer, offset); offset += jwtBuffer.length;
  authBuffer.writeUInt8(locationBuffer.length, offset++); // Location ID length
  locationBuffer.copy(authBuffer, offset);

  return authBuffer;
}

function createConnectRequest(targetHost, targetPort) {
  console.log(`Connecting to ${targetHost}:${targetPort} through proxy`)
  const hostBuffer = Buffer.from(targetHost);
  const buffer = Buffer.alloc(7 + hostBuffer.length);
  let offset = 0;

  buffer.writeUInt8(0x05, offset++); // SOCKS version
  buffer.writeUInt8(0x01, offset++); // CONNECT
  buffer.writeUInt8(0x00, offset++); // Reserved
  buffer.writeUInt8(0x03, offset++); // Address type: Domain
  buffer.writeUInt8(hostBuffer.length, offset++); // Domain name length
  hostBuffer.copy(buffer, offset); offset += hostBuffer.length;
  buffer.writeUInt16BE(targetPort, offset); // Port

  return buffer;
}

function connectThroughSocks5Proxy({ proxyHost, proxyPort, targetHost, targetPort, jwt, sccLocationId }) {
  return new Promise((resolve, reject) => {
    const client = new net.Socket();
    let stage = 0;

    client.connect(proxyPort, proxyHost, () => {
      client.write(createInitialRequest());
    });

    client.on('data', (data) => {
      console.log("stage",stage,"data",data);
      if (stage === 0) {
        if (data[1] !== 0x80) return reject(new Error('JWT auth not accepted'));
        client.write(createAuthenticationRequest(jwt, sccLocationId));
        stage++;
      } else if (stage === 1) {
        if (data[1] !== 0x00) return reject(new Error('JWT authentication failed'));
        console.log('Connected to target host', targetHost, targetPort);
        client.write(createConnectRequest(targetHost, targetPort));
        stage++;
      } else if (stage === 2) {
        if (data[1] !== 0x00) return reject(new Error('CONNECT command failed'));
        return resolve(client); // SOCKS5 tunnel is ready
      }
    });

    client.on('error', reject);
  });
}

module.exports = { connectThroughSocks5Proxy };
