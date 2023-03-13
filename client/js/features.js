const url = window.location.href;
// const url = "http://krakkein-loggions.godaddysites.com/";
// const url ="https://www.tutorialstonight.com";
// const url = "https://www.flipkart.com";

const urlDomain = window.location.hostname;
// const urlDomain = url.match(/^(?:https?:\/\/)?(?:[^@\n]+@)?(?:www\.)?([^:/\n?]+)/)[1];
// const urlDomain = "flipkart.com";

const urlOrigin = window.location.origin;
// const urlOrigin = "www." + urlDomain;
// const urlOrigin = "www.flipkart.com";

const onlyDomain = urlDomain.replace("www.", "");

console.log("url: " + url);
console.log("urlDomain: " + urlDomain);
console.log("urlOrigin: " + urlOrigin);
console.log("onlyDomain: " + onlyDomain);

let result = {};

function makeRequest(url, method, callback, feature, action = "jsonRequest") {
  chrome.runtime.sendMessage(
    { action: action, url, method },
    function (response) {
      if (response.data) {
        // console.log("Hello: "+ feature + " " +response.data)
        callback(response.data);
      } else {
        console.log("Error in: " + feature);
        // console.error(response.error);s
      }
    }
  );
}

function makePredictionRequest(
  url,
  method,
  body,
  callback,
  feature,
  action = "predictionRequest"
) {
  chrome.runtime.sendMessage(
    { action: action, url, method, body },
    function (response) {
      if (response.data) {
        // console.log("Hello: "+ feature + " " +response.data)
        callback(response.data);
      } else {
        console.log("Error in: " + feature);
        // console.error(response.error);
      }
    }
  );
}

// 1. SSLfinal_State
const sslFinalState = () => {
  let protocol = url.split(":")[0];
  console.log("protocol: " + protocol);
  if (protocol !== "https") {
    result["A.SSL_Final_State"] = 1;
  } else {
    makeRequest(
      `http://127.0.0.1:3000/check-ssl?onlyDomain=${encodeURIComponent(
        onlyDomain
      )}`,
      "GET",
      function (data) {
        console.log(data);

        let ssl_info = data;
        if (ssl_info["isCertAgeValid"] && ssl_info["isIssuerTrusted"]) {
          result["A.SSL_Final_State"] = -1;
        } else {
          result["A.SSL_Final_State"] = 0;
        }
      },
      "SSL"
    );
  }
};

// 2. URL_of_Anchor;
const urlOfAnchor = () => {
  try {
    let aTags = document.getElementsByTagName("a");
    // console.log(aTags);

    let phishCount = 0;
    let legitCount = 0;
    let allhrefs = "";

    const url_anchor_patt = RegExp(onlyDomain);
    // const url_anchor_patt = RegExp(onlyDomain, "g");

    for (let i = 0; i < aTags.length; i++) {
      let hrefs = aTags[i].getAttribute("href");
      if (!hrefs) continue;
      allhrefs += hrefs + "       ";
      if (url_anchor_patt.test(hrefs)) {
        legitCount++;
      } else if (
        hrefs.charAt(0) == "#" ||
        (hrefs.charAt(0) == "/" && hrefs.charAt(1) != "/") ||
        (hrefs.charAt(0) == "." &&
          hrefs.charAt(1) == "/" &&
          hrefs.charAt(2) != "/")
      ) {
        legitCount++;
      } else {
        phishCount++;
      }
    }
    let totalCount = phishCount + legitCount;
    let outRequest = (phishCount / totalCount) * 100;

    // console.log("Legit: "+legitCount)
    // console.log("Phish: "+phishCount)

    if (outRequest < 31) {
      result["B.Anchor"] = -1;
    } else if (outRequest >= 31 && outRequest <= 67) {
      result["B.Anchor"] = 0;
    } else {
      result["B.Anchor"] = 1;
    }
  } catch (error) {
    console.log("Error in Anchor Url: " + error);
  }
};

// 3. Prefix_Suffix;
const prefixSuffix = () => {
  const pre_suff_patt = /-/;
  if (pre_suff_patt.test(urlDomain)) {
    result["C.(-) Prefix/Suffix in domain"] = 1;
  } else {
    result["C.(-) Prefix/Suffix in domain"] = -1;
  }
};

// 4. web_traffic;
const webTraffic = () => {
  const options = {
    method: "GET",
    headers: {
      "X-RapidAPI-Key": "0fbba3cd37mshed2e6bf2968953bp14bf02jsnbc6aade2eb71off",
      "X-RapidAPI-Host": "similar-web.p.rapidapi.com",
    },
  };

  fetch(
    `https://similar-web.p.rapidapi.com/get-analysis?domain=${onlyDomain}`,
    options
  )
    .then((response) => response.json())
    .then((response) => {
      // console.log(response);
      let web_rank = response["GlobalRank"]["Rank"];
      if (web_rank < 150000) {
        result["D.Web_Traffic"] = -1;
      } else if (web_rank > 150000 && web_rank < 200000) {
        result["D.Web_Traffic"] = 0;
      } else {
        result["D.Web_Traffic"] = 1;
      }
    })
    .catch((err) => {
      console.log("Error in Web Traffic: " + err);
      result["D.Web_Traffic"] = 0;
    });
};

// 5. having_Sub_Domain;
const havingSubDomain = () => {
  if ((onlyDomain.match(RegExp("\\.", "g")) || []).length == 1) {
    result["E.Having Sub Domains"] = -1;
  } else if ((onlyDomain.match(RegExp("\\.", "g")) || []).length == 2) {
    result["E.Having Sub Domains"] = 0;
  } else {
    result["E.Having Sub Domains"] = 1;
  }
};

// 6. Request_URL;
const requestUrl = () => {
  try {
    var imgTags = document.getElementsByTagName("img");
    var phishCount = 0;
    var legitCount = 0;

    const req_url_patt = RegExp(onlyDomain);

    for (var i = 0; i < imgTags.length; i++) {
      let src = imgTags[i].getAttribute("src");

      if (!src) continue;
      if (req_url_patt.test(src)) {
        legitCount++;
      } else if (src.charAt(0) == "/" && src.charAt(1) != "/") {
        legitCount++;
      } else {
        phishCount++;
      }
    }

    var totalCount = phishCount + legitCount;
    var outRequest = (phishCount / totalCount) * 100;
    //alert(outRequest);

    if (outRequest < 22) {
      result["F.Request URL"] = -1;
    } else if (outRequest >= 22 && outRequest < 61) {
      result["F.Request URL"] = 0;
    } else {
      result["F.Request URL"] = 1;
    }
  } catch (error) {
    console.log("Error in Request Url: " + error);
  }
};

// 7. Links_in_tags;
const linksInTags = () => {
  // var mTags = document.getElementsByTagName("meta");
  var sTags = document.getElementsByTagName("script");
  var lTags = document.getElementsByTagName("link");

  let link_tags_patt = RegExp(onlyDomain, "g");

  let phishCount = 0;
  let legitCount = 0;

  let allhrefs = "sTags  ";

  for (var i = 0; i < sTags.length; i++) {
    var sTag = sTags[i].getAttribute("src");
    if (sTag != null) {
      allhrefs += sTag + "      ";
      if (link_tags_patt.test(sTag)) {
        legitCount++;
      } else if (sTag.charAt(0) == "/" && sTag.charAt(1) != "/") {
        legitCount++;
      } else {
        phishCount++;
      }
    }
  }

  allhrefs += "      lTags   ";
  for (var i = 0; i < lTags.length; i++) {
    var lTag = lTags[i].getAttribute("href");
    if (!lTag) continue;
    allhrefs += lTag + "       ";
    if (link_tags_patt.test(lTag)) {
      legitCount++;
    } else if (lTag.charAt(0) == "/" && lTag.charAt(1) != "/") {
      legitCount++;
    } else {
      phishCount++;
    }
  }

  let totalCount = phishCount + legitCount;
  let outRequest = (phishCount / totalCount) * 100;

  if (outRequest < 17) {
    result["G.Script & Link"] = -1;
  } else if (outRequest >= 17 && outRequest <= 81) {
    result["G.Script & Link"] = 0;
  } else {
    result["G.Script & Link"] = 1;
  }
};

// 8. Domain_registration_length , 11. Age of Domain, 15. DNS Record
const whoisInfo = () => {
  makeRequest(
    `http://127.0.0.1:3000/check-whois?onlyDomain=${encodeURIComponent(
      onlyDomain
    )}`,
    "GET",
    function (data) {
      // console.log(data);

      // console.log(data);

      // if data sent by server is -1 then the given domain is not registered
      if (data == "-1") {
        result["H.Domain_Reg_Length"] = 1;
        result["K.Age of Domain"] = 1;
        result["O.DNS Record"] = 1;
      } else {
        result["O.DNS Record"] = -1;

        let creationDate = new Date(data["Creation Date"].slice(0, 10));
        let updatedDate = new Date(data["Updated Date"].slice(0, 10));
        let expiryDate = new Date(
          data["Registry Expiry Date"]
            ? data["Registry Expiry Date"].slice(0, 10)
            : data["Registrar Registration Expiration Date"].slice(0, 10)
        );
        let currentDate = new Date(new Date().toJSON().slice(0, 10));

        // console.log(expiryDate);
        // console.log(currentDate)

        // Domain Registration Length
        let domain_reg_length = difference(currentDate, expiryDate);
        // console.log(domain_reg_length)

        if (domain_reg_length <= 365) {
          result["H.Domain_Reg_Length"] = 1;
        } else {
          result["H.Domain_Reg_Length"] = -1;
        }

        // Age of Domain
        let age_of_domain = difference(creationDate, currentDate);

        if (age_of_domain <= 180) {
          result["K.Age of Domain"] = 1;
        } else {
          result["K.Age of Domain"] = -1;
        }
      }
    },
    "WhoIs"
  );
};

function difference(date1, date2) {
  const date1utc = Date.UTC(
    date1.getFullYear(),
    date1.getMonth(),
    date1.getDate()
  );
  const date2utc = Date.UTC(
    date2.getFullYear(),
    date2.getMonth(),
    date2.getDate()
  );
  let day = 1000 * 60 * 60 * 24;
  return (date2utc - date1utc) / day;
}

// 9. SFH;
const sfh = () => {
  let patt = RegExp(onlyDomain, "g");
  var forms = document.getElementsByTagName("form");
  var res = -1;

  for (var i = 0; i < forms.length; i++) {
    var action = forms[i].getAttribute("action");
    if (!action || action == "") {
      res = 1;
      break;
    } else if (!(action.charAt(0) == "/" || patt.test(action))) {
      res = 0;
    }
  }
  result["I.SFH"] = res;
};

// 10. Google_Index;
const googleIndex = () => {
  makeRequest(
    `http://127.0.0.1:3000/check-index-new?onlyDomain=${encodeURIComponent(
      onlyDomain
    )}`,
    "GET",
    function (data) {
      // console.log(data);
      if (data == "1") {
        result["J.Google_Index"] = 1;
      } else {
        result["J.Google_Index"] = -1;
      }
    },
    "Google_Index"
  );
};

// 12. Page_Rank;
const pageRank = () => {
  // cors
  let globalRank;
  fetch("https://www.checkpagerank.net/index.php", {
    method: "POST",
    mode: "no-cors",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "name=" + onlyDomain,
  })
    .then((response) => response.text())
    .then((text) => {
      let match = text.match(/Global Rank: ([0-9]+)/);
      if (match) {
        globalRank = parseInt(match[1]);
        if (globalRank > 0 && globalRank < 100000) {
          result["L.Global Rank"] = 1;
        } else {
          result["L.Global Rank"] = -1;
        }
      } else {
        result["L.Global Rank"] = -1;
      }
    })
    .catch((error) => {
      console.error("Error in Page Rank " + error);
      result["L.Global Rank"] = -1;
    });
};

// 13. having_IP_Address;
const havingIpAddress = () => {
  var patt1 = /(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]?[0-9])(\.|$){4}/;
  var patt2 = /(0x([0-9][0-9]|[A-F][A-F]|[A-F][0-9]|[0-9][A-F]))(\.|$){4}/;
  var ip = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;

  if (ip.test(urlDomain) || patt1.test(urlDomain) || patt2.test(urlDomain)) {
    result["M.IP Address"] = 1;
  } else {
    result["M.IP Address"] = -1;
  }
};

// 14. Statistical_report;
const statsReport = () => {
  let ip_address = "";

  makeRequest(
    `http://127.0.0.1:3000/check-dns?onlyDomain=${encodeURIComponent(
      onlyDomain
    )}`,
    "GET",
    function (data) {
      // ip_address = text;
      console.log("Data from dns ip: " + data);
      ip_address = data;

      var re =
        /at.ua|usa.cc|baltazarpresentes.com.br|pe.hu|esy.es|hol.es|sweddy.com|myjino.ru|96.lt|ow.ly/;
      var url_match = url.match(re);

      var ip_re =
        /146.112.61.108|213.174.157.151|121.50.168.88|192.185.217.116|78.46.211.158|181.174.165.13|46.242.145.103|121.50.168.40|83.125.22.219|46.242.145.98|107.151.148.44|107.151.148.107|64.70.19.203|199.184.144.27|107.151.148.108|107.151.148.109|119.28.52.61|54.83.43.69|52.69.166.231|216.58.192.225|118.184.25.86|67.208.74.71|23.253.126.58|104.239.157.210|175.126.123.219|141.8.224.221|10.10.10.10|43.229.108.32|103.232.215.140|69.172.201.153|216.218.185.162|54.225.104.146|103.243.24.98|199.59.243.120|31.170.160.61|213.19.128.77|62.113.226.131|208.100.26.234|195.16.127.102|195.16.127.157|34.196.13.28|103.224.212.222|172.217.4.225|54.72.9.51|192.64.147.141|198.200.56.183|23.253.164.103|52.48.191.26|52.214.197.72|87.98.255.18|209.99.17.27|216.38.62.18|104.130.124.96|47.89.58.141|78.46.211.158|54.86.225.156|54.82.156.19|37.157.192.102|204.11.56.48|110.34.231.42/;
      var ip_match = ip_address.match(ip_re);

      if (url_match) {
        result["N.Statistical Report"] = 1;
      } else if (ip_match) {
        result["N.Statistical Report"] = 1;
      } else {
        result["N.Statistical Report"] = -1;
      }
    },
    "Stats_Report",
    "textRequest"
  );

  // fetch(
  //   `http://127.0.0.1:3000/check-dns?onlyDomain=${encodeURIComponent(
  //     onlyDomain
  //   )}`
  // )
  //   .then((response) => response.text())
  //   .then((text) => {
  //     // console.log(text);
  //     ip_address = text;

  //     var re =
  //       /at.ua|usa.cc|baltazarpresentes.com.br|pe.hu|esy.es|hol.es|sweddy.com|myjino.ru|96.lt|ow.ly/;
  //     var url_match = url.match(re);

  //     var ip_re =
  //       /146.112.61.108|213.174.157.151|121.50.168.88|192.185.217.116|78.46.211.158|181.174.165.13|46.242.145.103|121.50.168.40|83.125.22.219|46.242.145.98|107.151.148.44|107.151.148.107|64.70.19.203|199.184.144.27|107.151.148.108|107.151.148.109|119.28.52.61|54.83.43.69|52.69.166.231|216.58.192.225|118.184.25.86|67.208.74.71|23.253.126.58|104.239.157.210|175.126.123.219|141.8.224.221|10.10.10.10|43.229.108.32|103.232.215.140|69.172.201.153|216.218.185.162|54.225.104.146|103.243.24.98|199.59.243.120|31.170.160.61|213.19.128.77|62.113.226.131|208.100.26.234|195.16.127.102|195.16.127.157|34.196.13.28|103.224.212.222|172.217.4.225|54.72.9.51|192.64.147.141|198.200.56.183|23.253.164.103|52.48.191.26|52.214.197.72|87.98.255.18|209.99.17.27|216.38.62.18|104.130.124.96|47.89.58.141|78.46.211.158|54.86.225.156|54.82.156.19|37.157.192.102|204.11.56.48|110.34.231.42/;
  //     var ip_match = ip_address.match(ip_re);

  //     if (url_match) {
  //       result["N.Statistical Report"] = 1;
  //     } else if (ip_match) {
  //       result["N.Statistical Report"] = 1;
  //     } else {
  //       result["N.Statistical Report"] = -1;
  //     }
  //   })
  //   .catch((error) => {
  //     console.error("Error in Stats Report: " + error);
  //   });
};

// 15. DNSRecord; Done above

// 16. Shortining_Service
const shortService = () => {
  if (onlyDomain.length < 7) {
    result["P.Tiny URL"] = 1;
  } else {
    result["P.Tiny URL"] = -1;
  }
};

// 17. Abnormal_URL;
const abnormalUrl = () => {
  result["Q.Abnormal URL"] = -1;
};

// 18. URL_Length;
const urlLength = () => {
  if (url.length < 54) {
    result["R.URL Length"] = -1;
  } else if (url.length >= 54 && url.length <= 75) {
    result["R.URL Length"] = 0;
  } else {
    result["R.URL Length"] = 1;
  }
};

// 19. having_At_Symbol;
const havingAtSymbol = () => {
  const at_patt = /@/;
  if (at_patt.test(url)) {
    result["S.@ Symbol"] = 1;
  } else {
    result["S.@ Symbol"] = -1;
  }
};

// 20. on_mouseover
// cors error
// since modern browsers do not allow status bar customization we hard code this value as -1
const onMouseOver = () => {
  result["T.on_mouseover"] = -1;
};

// 21. HTTPS_token;
const httpsToken = () => {
  let match = urlDomain.match(/https:\/\/|http:\/\//);
  try {
    if (match) {
      result["U.HTTPS_token"] = 1;
    } else {
      result["U.HTTPS_token"] = -1;
    }
  } catch (error) {
    console.log("This is the error " + error);
    result["U.HTTPS_token"] = 1;
  }
};

// 22. Links_pointing_to_page;
const LinksPointingToPage = (r) => {
  makeRequest(
    `http://127.0.0.1:3000/check-links?url=${encodeURIComponent(url)}`,
    "GET",
    function (data) {
      let numBacklinks = parseInt(data);
      // console.log("Number of Links Pointing to page: " + numBacklinks);
      if (numBacklinks >= 0 && numBacklinks <= 3) {
        result["V.Links_Pointing"] = 1;
      } else if (numBacklinks >= 4 && numBacklinks <= 10) {
        result["V.Links_Pointing"] = 0;
      } else if (numBacklinks == -1) {
        console.log("Error in fetching Links pointing");
      } else {
        result["V.Links_Pointing"] = -1;
      }

      r();
    },
    "LinksPointingToPage",
    "textRequest"
  );
};

// 23. Redirect;
const redirect = () => {
  if (url.lastIndexOf("//") > 7) {
    result["W.Redirecting using //"] = 1;
  } else {
    result["W.Redirecting using //"] = -1;
  }
};

// Calling of Functions
// sslFinalState();
urlOfAnchor();
prefixSuffix();
webTraffic();
havingSubDomain();
requestUrl();
linksInTags();
whoisInfo();
sfh();
googleIndex();
pageRank();
havingIpAddress();
statsReport();
shortService();
abnormalUrl();
urlLength();
havingAtSymbol();
onMouseOver();
httpsToken();
LinksPointingToPage(handleResult);
redirect();

console.log(result);

function handleResult() {
  console.log(result);
  let result_array = [];

  result_array.push(result["A.SSL_Final_State"]);
  result_array.push(result["B.Anchor"]);
  result_array.push(result["C.(-) Prefix/Suffix in domain"]);
  result_array.push(result["D.Web_Traffic"]);
  result_array.push(result["E.Having Sub Domains"]);
  result_array.push(result["F.Request URL"]);
  result_array.push(result["G.Script & Link"]);
  result_array.push(result["H.Domain_Reg_Length"]);
  result_array.push(result["I.SFH"]);
  result_array.push(result["J.Google_Index"]);
  result_array.push(result["K.Age of Domain"]);
  result_array.push(result["L.Global Rank"]);
  result_array.push(result["M.IP Address"]);
  result_array.push(result["N.Statistical Report"]);
  result_array.push(result["O.DNS Record"]);
  result_array.push(result["P.Tiny URL"]);
  result_array.push(result["Q.Abnormal URL"]);
  result_array.push(result["R.URL Length"]);
  result_array.push(result["S.@ Symbol"]);
  result_array.push(result["T.on_mouseover"]);
  result_array.push(result["U.HTTPS_token"]);
  result_array.push(result["V.Links_Pointing"]);
  result_array.push(result["W.Redirecting using //"]);

  console.log(result_array);

  for (let i = 0; i < result_array.length; i++) {
    if (result_array[i] == undefined) {
      result_array[i] = 0;
    }
  }

  // console.log("hfxhfxhxhhgiugi")

  makePredictionRequest(
    "http://localhost:8000/predict",
    "POST",
    JSON.stringify(result_array),
    function (data) {
      // console.log(data);
      const final_prediction = parseInt(data.prediction);
      console.log("Final Verdict: " + final_prediction);
      if (final_prediction == 1) {
        alert("This is a Phishing Website!!");
      }
    },
    "Final_Prediction"
  );

  
  // fetch("http://localhost:8000/predict", {
  //   method: "POST",
  //   mode: "no-cors",
  //   headers: {
  //     "Content-Type": "application/json",
  //   },
  //   body: JSON.stringify(result_array),
  // })
  //   .then((response) => response.json())
  //   .then((data) => {
  //     // for (const key in data) {
  //     //   console.log(`${key}: ${data[key]}`);
  //     // }
  //     const final_prediction = parseInt(data.prediction);
  //     console.log("Final Verdict: " + final_prediction);
  //     if (final_prediction == 1) {
  //       alert("This is a Phishing Website!!");
  //     }
  //   })
  //   .catch(function (error) {
  //     console.log("Final Error: " + error);
  //   });
}
