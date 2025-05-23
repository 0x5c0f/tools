/**
 * 网页翻译助手 - 初始化脚本
 * 负责初始化translate.js和自定义UI
 */

// 等待translate.js和UI加载完成
function initTranslate() {
  // 确保translate对象已加载
  if (typeof window.translate === 'undefined') {
    console.error('translate.js 未正确加载');
    return;
  }
  
  console.log('translate.js 已加载，版本：' + window.translate.version);
  
  // 配置忽略翻译的class
  window.translate.ignore.class.push('notranslate');
  
  // 创建自定义UI
  const ui = window.createTranslateUI();
  
  // 从存储加载设置
  chrome.storage.sync.get(['translateSettings'], function(result) {
    const settings = result.translateSettings || {
      draggable: true,
      collapsed: true
    };
    
    // 应用设置
    if (settings.collapsed) {
      document.getElementById('translate-ui-container').classList.add('collapsed');
    }
  });
  
  // 从服务器加载支持的语言列表
  window.translate.request.post(window.translate.request.api.language, {}, function(data) {
    if (data.result == 0) {
      console.error('加载语言列表失败: ' + data.info);
      ui.showStatus('加载语言列表失败');
      return;
    }
    
    // 获取当前语言
    const currentLang = window.translate.language.getCurrent();
    
    // 更新UI中的语言选项
    ui.updateLanguages(data.list, currentLang);
    
    // 绑定翻译按钮点击事件
    document.getElementById('translate-ui-button').addEventListener('click', function() {
      const selectedLang = document.getElementById('translate-ui-select').value;
      
      // 显示翻译中状态
      ui.setButtonState(true);
      ui.showStatus('正在翻译...');
      
      try {
       // 使用正确的API执行翻译 - 使用changeLanguage而不是to
       window.translate.changeLanguage(selectedLang);
       
       // 保存用户选择的语言
       window.translate.storage.set('to', selectedLang);
       
       // 保存设置
       chrome.storage.sync.set({
         translateSettings: {
           draggable: true,
           collapsed: document.getElementById('translate-ui-container').classList.contains('collapsed')
         }
       });
        
        // 恢复按钮状态
        setTimeout(() => {
          ui.setButtonState(false);
          ui.showStatus('翻译完成');
        }, 1000);
      } catch (error) {
        console.error('翻译失败:', error);
        ui.showStatus('翻译失败: ' + error.message);
        
        // 恢复按钮状态
        setTimeout(() => {
          ui.setButtonState(false);
        }, 2000);
      }
    });
  });
}

// 在页面加载完成后初始化
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', function() {
    // 延迟一点执行，确保translate.js已完全加载
    setTimeout(initTranslate, 300);
  });
} else {
  // 延迟一点执行，确保translate.js已完全加载
  setTimeout(initTranslate, 300);
}
