
const PERSISTENCE_ATTR = 'data-persist';

function saveElementValue(element) {
  if (typeof element === 'string') {
    element = document.querySelector(element);
  }
  const key = element.getAttribute(PERSISTENCE_ATTR) || element.id || element.name;
  if (key) {
    const value = element.type === 'checkbox' ? element.checked : element.value;
    localStorage.setItem(key, JSON.stringify(value));
  }
}

function restoreElementValue(element) {
  const key = element.getAttribute(PERSISTENCE_ATTR) || element.id || element.name;
  if (key) {
    const value = JSON.parse(localStorage.getItem(key));
    if (value !== null) {
      if (element.type === 'checkbox') {
        element.checked = value;
      } else {
        element.value = value;
      }
    }
  }
}

function initFormPersistence() {
  const elements = document.querySelectorAll(`[${PERSISTENCE_ATTR}]`);
  console.log(elements);
  elements.forEach(element => {
    restoreElementValue(element);
    element.addEventListener('change', () => saveElementValue(element));
    if (element.tagName === 'INPUT' || element.tagName === 'TEXTAREA') {
      element.addEventListener('input', () => saveElementValue(element));
    }
  });
}

// 导出公共 API
export { initFormPersistence, saveElementValue, restoreElementValue };