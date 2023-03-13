chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {
  if (request.action == "jsonRequest") {
    fetch(request.url, {
      method: request.method,
      headers: {
        "Content-Type": "application/json",
      },
    })
      .then((response) => {
        // console.log(response);
        return response.json();
      })
      .then((data) => {
        console.log(data);
        sendResponse({ data });
      })
      .catch((error) => {
        console.log(error);
        sendResponse({ error });
      });
  } else if (request.action == "textRequest") {
    fetch(request.url, {
      method: request.method,
      headers: {
        "Content-Type": "application/json",
      },
    })
      .then((response) => {
        // console.log(response);
        return response.text();
      })
      .then((data) => {
        console.log(data);
        sendResponse({ data });
      })
      .catch((error) => {
        console.log(error);
        sendResponse({ error });
      });
  } else if (request.action == "predictionRequest") {
    fetch(request.url, {
      method: request.method,
      headers: {
        "Content-Type": "application/json",
      },
      body: request.body
    })
      .then((response) => {
        console.log(response);
        return response.json();
      })
      .then((data) => {
        console.log(data);
        sendResponse({ data });
      })
      .catch((error) => {
        console.log(error);
        sendResponse({ error });
      });
  }
  return true;
});
