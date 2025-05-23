/**
 * 网页翻译助手 - 自定义V2风格UI
 * 提供美观的翻译控制界面
 */

// 创建并注入自定义UI
function createTranslateUI() {
  // UI样式定义
  const translateUIStyles = `
.translate-ui-container {
  position: fixed;
  top: 20px;
  right: 20px;
  background-color: white;
  border-radius: 50px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
  padding: 10px;
  z-index: 9999;
  font-family: Arial, sans-serif;
  font-size: 14px;
  display: flex;
  align-items: center;
  transition: all 0.3s ease;
  width: auto;
  min-width: 44px;
  max-width: 400px;
  overflow: hidden;
}

.translate-ui-container.collapsed {
  width: 44px;
  height: 44px;
}

.translate-ui-logo {
  width: 44px;
  height: 44px;
  background-color: #4285f4;
  border-radius: 50%;
  margin-right: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: white;
  font-weight: bold;
  font-size: 16px;
  flex-shrink: 0;
  cursor: move;
  transition: all 0.3s ease;
}

.translate-ui-content {
  display: flex;
  align-items: center;
  transition: all 0.3s ease;
}

.translate-ui-container.collapsed .translate-ui-content {
  display: none;
}

.translate-ui-select {
  padding: 5px;
  border: 1px solid #ddd;
  border-radius: 4px;
  margin-right: 10px;
  outline: none;
  width: 150px;
  margin-right: 8px;
}

.translate-ui-button {
  background-color: #4285f4;
  color: white;
  border: none;
  padding: 5px 10px;
  border-radius: 4px;
  cursor: pointer;
  font-size: 14px;
  white-space: nowrap;
}

.translate-ui-button:hover {
  background-color: #3367d6;
}

.translate-ui-button:disabled {
  background-color: #cccccc;
  cursor: not-allowed;
}

.translate-ui-status {
  position: absolute;
  bottom: -30px;
  left: 0;
  right: 0;
  text-align: center;
  background-color: rgba(0, 0, 0, 0.7);
  color: white;
  padding: 5px;
  border-radius: 4px;
  font-size: 12px;
  opacity: 0;
  transition: opacity 0.3s ease;
}

.translate-ui-status.show {
  opacity: 1;
}

@media (max-width: 480px) {
  .translate-ui-container {
    max-width: 280px;
    flex-wrap: wrap;
  }
  
  .translate-ui-select {
    margin-bottom: 8px;
    width: 100%;
    margin-right: 0;
  }
  
  .translate-ui-button {
    width: 100%;
  }
}`;

  // 注入样式
  const styleElement = document.createElement('style');
  styleElement.textContent = translateUIStyles;
  document.head.appendChild(styleElement);
  
  // 创建UI元素
  const container = document.createElement('div');
  container.className = 'translate-ui-container collapsed';
  container.id = 'translate-ui-container';
  
  const logo = document.createElement('div');
  logo.className = 'translate-ui-logo';
  logo.textContent = 'T';
  
  const content = document.createElement('div');
  content.className = 'translate-ui-content';
  
  const select = document.createElement('select');
  select.className = 'translate-ui-select notranslate';
  select.id = 'translate-ui-select';
  
  const translateButton = document.createElement('button');
  translateButton.className = 'translate-ui-button';
  translateButton.textContent = '翻译';
  translateButton.id = 'translate-ui-button';
  
  const status = document.createElement('div');
  status.className = 'translate-ui-status';
  status.id = 'translate-ui-status';
  
  // 组装UI
  content.appendChild(select);
  content.appendChild(translateButton);
  content.appendChild(status);
  container.appendChild(logo);
  container.appendChild(content);
  document.body.appendChild(container);

  // 添加拖动功能
  let isDragging = false;
  let offsetX, offsetY;
  
  logo.style.cursor = 'move';
  
  logo.addEventListener('mousedown', function(e) {
    isDragging = true;
    offsetX = e.clientX - container.getBoundingClientRect().left;
    offsetY = e.clientY - container.getBoundingClientRect().top;
    container.style.transition = 'none';
    e.preventDefault();
  });

  document.addEventListener('mousemove', function(e) {
    if (!isDragging) return;
    
    let newX = e.clientX - offsetX;
    let newY = e.clientY - offsetY;
    
    newX = Math.max(0, Math.min(newX, window.innerWidth - container.offsetWidth));
    newY = Math.max(0, Math.min(newY, window.innerHeight - container.offsetHeight));
    
    container.style.left = newX + 'px';
    container.style.top = newY + 'px';
    container.style.right = 'auto';
  });

  document.addEventListener('mouseup', function() {
    isDragging = false;
    container.style.transition = 'all 0.3s ease';
  });

  // 添加折叠/展开事件
  logo.addEventListener('click', function() {
    container.classList.toggle('collapsed');
  });

  // 返回UI引用
  return {
    container,
    select,
    translateButton,
    status,
    
    showStatus: function(message, duration = 3000) {
      status.textContent = message;
      status.classList.add('show');
      
      setTimeout(function() {
        status.classList.remove('show');
      }, duration);
    },
    
    updateLanguages: function(languages, currentLanguage) {
      select.innerHTML = '';
      
      languages.forEach(lang => {
        const option = document.createElement('option');
        option.value = lang.id;
        option.textContent = lang.name;
        option.classList.add('notranslate');
        
        if (currentLanguage && currentLanguage === lang.id) {
          option.selected = true;
        }
        
        select.appendChild(option);
      });
    },
    
    setButtonState: function(isTranslating) {
      if (isTranslating) {
        translateButton.disabled = true;
        translateButton.textContent = '翻译中...';
      } else {
        translateButton.disabled = false;
        translateButton.textContent = '翻译';
      }
    }
  };
}

// 导出UI创建函数
if (typeof window !== 'undefined') {
  window.createTranslateUI = createTranslateUI;
}
