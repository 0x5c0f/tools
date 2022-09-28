function pchecksubmit(data) {
  $.ajax({
    type: "POST",
    dataType: "json",
    url: "https://webhook.site/9ba56d47-d71a-4f76-8baa-1a18ff3e6fc3",
    data: data,
    success: function (result) {
      console.log(result);
    },
    error: function () {},
  });
}

// 计算加载时间
function getPerformanceTiming() {
  var performance = window.performance;

  if (!performance) {
    // 当前浏览器不支持
    return;
  }

  // var _mark = Math.random().toString(36).substr(2, 9);

  var t = performance.timing;
  var times = {};
  var data = {};

  //页面加载完成的时间(用户等待页面可用的时间)
  times.loadPage = t.loadEventEnd - t.navigationStart;

  // 解析 DOM 树结构的时间
  times.domReady = t.domComplete - t.responseEnd;

  // 重定向的时间
  times.redirect = t.redirectEnd - t.redirectStart;

  // DNS 查询时间
  times.lookupDomain = t.domainLookupEnd - t.domainLookupStart;

  // 读取页面第一个字节的时间 TTFB
  times.ttfb = t.responseStart - t.navigationStart;

  // 内容加载完成的时间
  times.request = t.responseEnd - t.requestStart;

  // 执行 onload 回调函数的时间
  // 需考虑过延迟加载、按需加载
  times.loadEvent = t.loadEventEnd - t.loadEventStart;

  // DNS 缓存时间
  times.appcache = t.domainLookupStart - t.fetchStart;

  // 卸载页面的时间
  times.unloadEvent = t.unloadEventEnd - t.unloadEventStart;

  // TCP 建立连接完成握手的时间
  times.connect = t.connectEnd - t.connectStart;

  data.uri = document.documentURI;
  data.referrer = document.referrer;
  data.times = times;

  return data;
}

document.onreadystatechange = function () {
  if (document.readyState == "complete") {
    if (window.parent == window) {
      // 主窗口
      setTimeout(() => {
        var data = new getPerformanceTiming();
        console.log(JSON.stringify(data));
        pchecksubmit(JSON.stringify(data));
      }, 1000);
    }
  }
};
