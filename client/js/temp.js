// 2. URL_of_Anchor;

const urlOfAnchor = () => {
  fetch(`http://127.0.0.1:3000/check-anchorUrl?url=${encodeURIComponent(url)}`)
    .then((response) => response.json())
    .then((data) => {
      const aTags = Object.values(data);
      // console.log(aTags);

      let phishCount = 0;
      let legitCount = 0;
      let allhrefs = "";

      const url_anchor_patt = RegExp(onlyDomain);
      // const url_anchor_patt = RegExp(onlyDomain, "g");

      for (let i = 0; i < aTags.length; i++) {
        let hrefs = aTags[i];
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
    })
    .catch((error) => {
      console.log("Error in URL Anchor: " + error);
      result["B.Anchor"] = 0;
    });
};