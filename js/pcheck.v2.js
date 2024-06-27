// function sendPerformanceData(method, data) {
//   let apiUrl = "https://tools.0x5c0f.cc";
  
//   console.log("performance data:", data);
  
//   fetch(apiUrl, {
//     method: method,
//     headers: {
//       "Content-Type": "application/json",
//     },
//     body: JSON.stringify(data),
//   })
//     .then((response) => console.log("Performance data sent:", response))
//     .catch((error) => console.error("Error sending performance data:", error));
// }

function sendPerformanceData(method, data) {
  let apiUrl = "https://tools.0x5c0f.cc";
  
  console.log("performance data:", data);
  
  if (method === "POST") {
    fetch(apiUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(data),
    })
      .then((response) => console.log("Performance data sent:", response))
      .catch((error) => console.error("Error sending performance data:", error));
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
      .then((response) => console.log("Performance data sent:", response))
      .catch((error) => console.error("Error sending performance data:", error));
  }
}

// 使用Performance Observer监听性能条目
let performanceObserver = new PerformanceObserver((list) => {
  let entries = list.getEntries();
  let performanceData = {};
  
  entries.forEach((entry) => {
    if (entry.entryType === 'navigation') {
      performanceData = {
        dnsTime: {
          value: entry.domainLookupEnd - entry.domainLookupStart,
          description: "DNS查询时间",
        },
        redirectTime: {
          value: entry.redirectEnd - entry.redirectStart,
          description: "重定向时间",
        },
        domLoadTime: {
          value: entry.domComplete - entry.domLoading,
          description: "DOM结构解析时间",
        },
        frontendPerformance: {
          value: entry.loadEventEnd - entry.startTime,
          description: "页面完全加载时间",
        },
        ttfbTime: {
          value: entry.responseStart - entry.startTime,
          description: "读取页面第一个字节时间",
        },
        contentLoadTime: {
          value: entry.loadEventEnd - entry.responseEnd,
          description: "内容加载时间",
        },
        onLoadCallbackTime: {
          value: entry.loadEventEnd - entry.loadEventStart,
          description: "执行onload回调函数时间",
        },
        dnsCacheTime: {
          value: entry.domainLookupStart - entry.fetchStart,
          description: "DNS缓存时间",
        },
        unloadTime: {
          value: entry.unloadEventEnd - entry.unloadEventStart,
          description: "卸载页面时间",
        },
        tcpHandshakeTime: {
          value: entry.connectEnd - entry.connectStart,
          description: "TCP握手时间",
        },
        domain: {
          value: window.location.hostname,
          description: "当前站点",
        },
      };
    }
  });

  // 调用发送性能数据的方法，传入 'POST' 作为参数
  sendPerformanceData("POST", performanceData);
});

// 开始观察性能条目
performanceObserver.observe({type: 'navigation', buffered: true});

// 你也可以在任何时候停止观察
// performanceObserver.disconnect();