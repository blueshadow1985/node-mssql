async function getJWTToken(clientid, clientsecret, tokenurl) {
    const basicAuth = Buffer.from(`${clientid}:${clientsecret}`).toString('base64');
    const response = await fetch(tokenurl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${basicAuth}`
      },
      body: new URLSearchParams({ grant_type: 'client_credentials' })
    });
  
    const json = await response.json();
    return json.access_token;
}

module.exports = {getJWTToken};
