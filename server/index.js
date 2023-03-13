const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const cors = require("cors");
const port = 3000;

const axios = require("axios");
const cheerio = require("cheerio");
const https = require("https");
// const whois = require("node-whois");
const whois = require("whois");
const dns = require("dns");
const puppeteer = require("puppeteer");
// const AlexaRank = require("alexa-rank-nodejs");

// const whois = require("whois-json");

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
  res.setHeader("Access-Control-Allow-Headers", "content-type, accept");
  next();
});

// We are using our packages here
app.use(bodyParser.json()); // to support JSON-encoded bodies

app.use(
  bodyParser.urlencoded({
    // to support URL-encoded bodies
    extended: true,
  })
);
app.use(cors());

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

//You can use this to check if your server is working
app.get("/", (req, res) => {
  res.send("Welcome to your server");
});

// SSL Certificate
app.get("/check-ssl", async (req, res) => {
  try {
    ssl_info = {};

    const trusted_issuers = [
      "GeoTrust",
      "GoDaddy",
      "Network Solutions",
      "Thawte",
      "Comodo",
      "VeriSign",
      "RapidSSL",
      "Sectigo",
      "Digicert",
      "Actalis",
      "Certum",
      "Entrust",
      "GlobalSign",
      "SecureTrust",
      "UserTrust",
      "R3",
      "IdenTrust",
      "Symantec",
      "Cloudflare",
      "Amazon",
      "GTS",
    ];

    let hostname = "www." + req.query.onlyDomain;
    console.log(hostname);
    https.get(`https://${hostname}`, async (response) => {
      // const certificate = await response.socket.getPeerCertificate();
      const certificate = await response.connection.getPeerCertificate();
      // console.log(certificate)
      if (certificate && certificate.issuer && certificate.issuer.CN) {
        // Calculating certificate age
        let valid_from_date = new Date(certificate.valid_from);
        let valid_to_date = new Date(certificate.valid_to);
        let certificate_age = valid_to_date - valid_from_date;
        let certificate_age_months = (
          certificate_age /
          (1000 * 60 * 60 * 24 * 30.44)
        ).toFixed(0);
        // console.log(certificate_age_months);
        if (certificate_age_months >= 3) {
          ssl_info["isCertAgeValid"] = true;
        } else {
          ssl_info["isCertAgeValid"] = false;
        }

        // Is Issuer Trusted or not

        let issuer_name = certificate.issuer.CN;
        // console.log(issuer_name)
        console.log("*****************************************");
        for (let i in trusted_issuers) {
          if (
            issuer_name.toLowerCase().includes(trusted_issuers[i].toLowerCase())
          ) {
            ssl_info["isIssuerTrusted"] = true;
            break;
          } else {
            ssl_info["isIssuerTrusted"] = false;
          }
        }
      } else {
        console.log("BBBBingo");
        ssl_info["isCertAgeValid"] = false;
        ssl_info["isIssuerTrusted"] = false;
      }
      res.send(ssl_info);
    });
  } catch (error) {
    console.error("Error in SSL: " + err);
    ssl_info["isCertAgeValid"] = false;
    ssl_info["isIssuerTrusted"] = false;
    // Send an appropriate error response to the client
    res.status(500).send("Something went wrong in SSL!");
  }
});

// Domain Registration Length: Who is
app.get("/check-whois", async (req, res) => {
  let onlyDomain = req.query.onlyDomain ? req.query.onlyDomain : "";
  // let onlyDomain = "gov.uk";
  // console.log(onlyDomain)
  whois.lookup(onlyDomain, function (err, data) {
    if (err) {
      console.log("This is the error: " + err);
      res.status(500).send({ error: err });
    } else if (data.indexOf("No match for domain") != -1) {
      res.send("-1");
    } else {
      const parsedData = parseWhoisData(data);
      res.send(parsedData);
      // console.log(parsedData);
      // res.send({ data });
    }
  });
});

function parseWhoisData(data) {
  const lines = data.split("\n");
  const parsedData = {};
  let currentKey = "";

  for (const line of lines) {
    if (line.includes(":")) {
      const keyValue = line.split(":", 2);
      const key = keyValue[0].trim();
      const value = keyValue[1].trim();
      parsedData[key] = value;
      currentKey = key;
    } else if (line.startsWith(" ") && currentKey) {
      parsedData[currentKey] += ` ${line.trim()}`;
    }
  }

  return parsedData;
}

// Statistical Report
app.get("/check-dns", async (req, res) => {
  let onlyDomain = req.query.onlyDomain;
  console.log("idsbv -> " + onlyDomain);
  dns.lookup(onlyDomain, (err, address, family) => {
    if (err) {
      console.log("Error in check dns " + err);
      // throw err;
    } else {
      console.log(`The IP address of ${onlyDomain} is:` + address + "check");
      res.send(address);
    }
  });
});

// Google Index
app.get("/check-index", async (req, res) => {
  let onlyDomain = req.query.onlyDomain;
  await axios
    .get(`https://www.google.com/search?q=site:${onlyDomain}`)
    .then((response) => {
      console.log(onlyDomain);
      if (response.data.indexOf("did not match any documents") !== -1) {
        res.send("1");
        console.log("The website is not indexed by Google");
      } else {
        res.send("-1");
        console.log("The website is indexed by Google");
      }
    })
    .catch((error) => {
      console.log(error);
    });
});

app.get("/check-index-new", async (req, res) => {
  try {
    let onlyDomain = req.query.onlyDomain;
    // console.log("idsbv -> "+ onlyDomain)
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    await page.goto(`https://www.google.com/search?q=site:${onlyDomain}`);
    await page.waitForSelector("#result-stats");
    const numlinks = parseInt(
      await page.$eval("#result-stats", (el) =>
        el.textContent.match(/About ([0-9,]+) results/)[1].replace(/,/g, "")
      )
    );
    console.log("Number of results in", onlyDomain, ":", numlinks);
    if (numlinks == 0) {
      res.send("1");
      console.log(`The website ${onlyDomain} is not indexed by Google`);
    } else {
      res.send("-1");
      console.log(`The website ${onlyDomain} is indexed by Google`);
    }
    await browser.close();
  } catch (error) {
    res.send("-1");
    console.log("Error in Google Index: " + error);
  }
});

// Links pointing to page
// Launching Headless Browser using puppeteer: Working
// const url = "https://www.snapdeal.com/";
app.get("/check-links", async (req, res) => {
  try {
    let fullUrl = req.query.url;
    // console.log("idsbv -> "+ onlyDomain)
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    await page.goto(
      "https://www.google.com/search?q=link:" + encodeURIComponent(fullUrl)
    );
    await page.waitForSelector("#result-stats");
    const numBacklinks = parseInt(
      await page.$eval("#result-stats", (el) =>
        el.textContent.match(/About ([0-9,]+) results/)[1].replace(/,/g, "")
      )
    );
    console.log("Number of pages linking to", fullUrl, ":", numBacklinks);
    res.send(numBacklinks.toString());
    await browser.close();
  } catch (error) {
    res.send("-1");
    console.log("Error Links Pointing: " + error);
  }
});

//Start your server on a specified port
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
