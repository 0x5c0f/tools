// 发送性能数据的方法
function sendPerformanceData(method, data) {
  let apiUrl = "https://tools.0x5c0f.cc";
  // let apiUrl = "https://webhook.site/de6825d9-e833-41ee-8d04-2b0d11f682ee";
  
  console.log("performance data:", data);
  
  if (method === "POST") {
    // 获取用户所在的ip信息
    // fetch("https://api.myip.la")
    //   .then((response) => response.text())
    //   .then((ipData) => {
    //     let dataToSend = {
    //       performanceData: data,
    //       userIP: ipData,
    //     };
    //     fetch(apiUrl, {
    //       method: "POST",
    //       headers: {
    //         "Content-Type": "application/json",
    //       },
    //       body: JSON.stringify(dataToSend),
    //     })
    //       .then((response) => console.log("Performance data sent:", response)) // 成功发送性能数据后的处理
    //       .catch((error) =>
    //         console.error("Error sending performance data:", error)
    //       ); // 发送性能数据失败时的处理
    //   })
    //   .catch((ipError) => console.error("Error fetching user IP:", ipError));

    fetch(apiUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(data),
    })
      .then((response) => console.log("Performance data sent:", response)) // 成功发送性能数据后的处理
      .catch((error) =>
        console.error("Error sending performance data:", error)
      ); // 发送性能数据失败时的处理
  } else if (method === "GET") {
    // 构建带有性能数据的GET请求URL
    let queryString = Object.keys(data)
      .map(
        (key) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(data[key].value)}`
      )
      .join("&");
    let getUrl = apiUrl + "?" + queryString;

    fetch(getUrl, {
      method: "GET",
    })
      .then((response) => console.log("Performance data sent:", response)) // 成功发送性能数据后的处理
      .catch((error) =>
        console.error("Error sending performance data:", error)
      ); // 发送性能数据失败时的处理
  }
}

// 当页面加载完成后执行
window.addEventListener("load", function () {
  // 延迟执行以确保获取准确的时间戳
  setTimeout(function () {
    // 获取页面加载性能数据
    let perfData = window.performance.timing;
    // 计算页面完全加载所需时间
    let pageLoadTime = perfData.loadEventEnd - perfData.navigationStart;

    // 构建需要发送的性能数据对象
    let performanceData = {
      dnsTime: {
        value: perfData.domainLookupEnd - perfData.domainLookupStart,
        description: "DNS查询时间",
      },
      redirectTime: {
        value: perfData.redirectEnd - perfData.redirectStart,
        description: "重定向时间",
      },
      domLoadTime: {
        value: perfData.domComplete - perfData.domLoading,
        description: "DOM结构解析时间",
      },
      frontendPerformance: {
        value: pageLoadTime,
        description: "页面完全加载时间",
      },
      ttfbTime: {
        value: perfData.responseStart - perfData.navigationStart,
        description: "读取页面第一个字节时间",
      },
      contentLoadTime: {
        value: perfData.loadEventEnd - perfData.responseEnd,
        description: "内容加载时间",
      },
      onLoadCallbackTime: {
        value: perfData.loadEventEnd - perfData.loadEventStart,
        description: "执行onload回调函数时间",
      },
      dnsCacheTime: {
        value: perfData.domainLookupStart - perfData.fetchStart,
        description: "DNS缓存时间",
      },
      unloadTime: {
        value: perfData.unloadEventEnd - perfData.unloadEventStart,
        description: "卸载页面时间",
      },
      tcpHandshakeTime: {
        value: perfData.connectEnd - perfData.connectStart,
        description: "TCP握手时间",
      },
      domain: {
        value: window.location.hostname,
        description: "当前站点",
      },
    };

    // 调用发送性能数据的方法，传入 'POST' 作为参数
    sendPerformanceData("POST", performanceData);
    // 调用发送性能数据的方法，传入 'GET' 作为参数
    // sendPerformanceData("GET", performanceData);
  }, 0);
});
