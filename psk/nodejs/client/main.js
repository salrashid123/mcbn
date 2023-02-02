const tls = require('tls');
const crypto = require('crypto')
const host = "localhost";
const port = 8081;

// acquire each participants keys within Confidential Space
// since this is just a demo, we'll pretend the CS VM acquired these keys using each participants 
// workload federation and KMS APIs
const alice = '2c6f63f8c0f53a565db041b91c0a95add8913fc102670589db3982228dbfed90';
const bob = 'b15244faf36e5e4b178d3891701d245f2e45e881d913b6c35c0ea0ac14224cc2';               
const carol = '3e2078d5cd04beabfa4a7a1486bc626d679184df2e0a2b9942d913d4b835516c';

// now sha256 of all the keys
const key = crypto.createHash('sha256').update(alice+bob+carol).digest('hex');

//console.log(key);
//key = '6d1bbd1e6235c9d9ec8cdbdf9b32d4d08304a7f305f7c6c67775130d914f4dc4';

// note, w'ere trusting bob and carol don't collude and send degenerate keys to compromise the final key
// but there are much better ways to derive a new key from a set of partials 
// using threshold encryption private keys
// here we're just doing something lazy of questionable merit by
// assuming assuming each keyshare isn't degenerate and the ordinal position of each key (i.,e alice is position 1, bob is 2, carol is 3) 


const USERS = {
  Client1: Buffer.from(key, 'hex'),
};
const options = {
    pskCallback(socket, id) {
        return { psk: USERS.Client1, identity: 'Client1' };
    }
}

var client = tls.connect(port,host, options, function () {
    client.write("GET / HTTP/1.0\n\n");
});

client.on("data", function (data) {
    console.log('Received: %s ',
        data.toString().replace(/(\n)/gm, ""));
    client.end();
});

client.on('close', function () {
    console.log("Connection closed");
});

client.on('error', function (error) {
    console.error(error);
    client.destroy();
});

//*********************** */

const https = require('https');
https.get('https://' + host + ':' + port + '/',options, (res) => {
    console.log('statusCode:', res.statusCode);
    res.on('data', (d) => {
        process.stdout.write(d);
    });
}).on('error', (e) => {
    console.error(e);
});