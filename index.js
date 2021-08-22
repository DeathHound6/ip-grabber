const e = require("express"),
    fs = require("fs"),
    geoip = require("geoip-lite"),
    proxy = require("ip2proxy-nodejs"),
    moment = require("moment"),
    app = e();

// comment the next line if your domain is not behind a proxy, example: cloudflare
app.set("trust proxy", true);

app.listen(3000, () => {
    console.log(`Started on port 3000`);
});

app.use(async (req, res, next) => {
    const time = Date.now();
    let ip = req.headers["cf-connecting-ip"] || req.connection.remoteAddress;
    ip = ip.replace(/\:\:[a-z0-9A-Z]+\:/gi, "");
    const ua = req.headers["user-agent"];
    const request = `${req.method} ${req.protocol
        }://${req.subdomains.reverse().map(e => `${e}.`)}${req.hostname}${req.originalUrl
        }`;
    const geo = geoip.lookup(ip);

    if (proxy.Open(`${__dirname}/IP2PROXY-IP-PROXYTYPE-COUNTRY-REGION-CITY-ISP-DOMAIN-USAGETYPE-ASN-LASTSEEN-THREAT-RESIDENTIAL.BIN`) == -1) return next();
    const proxies = {
        "- 1": "Errors",
        "0": "Not a proxy",
        "1": "A proxy",
        "2": "A data center IP address or search engine robot"
    };
    const ISP = proxy.getISP(ip);
    const prox = proxy.isProxy(ip);
    const dom = proxy.getDomain(ip);
    const proxType = proxy.getProxyType(ip);
    const threat = proxy.getThreat(ip);
    const country = proxy.getCountryLong(ip);
    const as = proxy.getAS(ip);
    const asn = proxy.getASN(ip);
    const last = proxy.getLastSeen(ip);          
    proxy.Close();

    fs.appendFile(`ip-grab.txt`, `IP: ${ip}
User Agent: ${ua}
Request URL: ${request}
Country: ${geo?.country || checkIP2LocValue(country)}
Region: ${checkIP2LocValue(geo?.region)}
City: ${checkIP2LocValue(geo?.city)}
Timezone: ${checkIP2LocValue(geo?.timezone)}
VPN/Proxy: ${proxies[String(prox)]}
ISP: ${checkIP2LocValue(ISP)}
Proxy Type: ${checkIP2LocValue(proxType)}
Domain/Hostname: ${checkIP2LocValue(dom)}
AS: ${checkIP2LocValue(as)}, ${checkIP2LocValue(asn)}
Last Seen: ${checkIP2LocValue(last)} days ago
Threat: ${checkIP2LocValue(threat)}
DateTime: ${moment(time).format("ddd MMM Do YYYY, HH:mm:ss")}\n\n`,
    (err) => {
        if (err) console.log(err);
    });
    next();
});

/**
 * @param {String} value 
 * @returns {Boolean}
 */
function checkIP2LocValue(value) {
    if (!value || value.replace(" ", "") == "-") return "Unknown";
    return value;
}