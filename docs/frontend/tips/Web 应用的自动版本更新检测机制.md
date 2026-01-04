# Web 应用的自动版本更新检测机制

## 什么是 Web 应用自动版本更新

Web 应用的自动版本更新是指在用户访问网站时，能够自动检测并通知用户有新版本可用，确保用户能够及时获取最新的功能和修复。这种机制在单页应用（SPA）中尤为重要，因为用户可能会长时间停留在一个页面上。

## 与传统应用更新的区别

### 传统桌面/移动应用

- 需要用户手动下载安装包
- 更新过程会中断当前使用
- 版本控制相对复杂，需要考虑兼容性问题

### Web 应用

- 服务器端部署后自动生效
- 客户端可以检测并提示更新
- 需要处理浏览器缓存和用户体验问题

## 实现原理：基于文件哈希的检测

现代前端构建工具（如 Webpack、Vite）在打包时会为资源文件生成内容哈希值，例如：

`<script type="module" crossorigin src="/assets/index-BSphUugS.js"></script>`

当文件内容发生变化时，哈希值也会改变，从而生成新的文件名。我们可以利用这一特性来检测版本更新。

## 实现步骤

### 1. 获取当前页面的资源链接

使用 AJAX 请求首页（`/`）获取最新的 HTML 内容：

```javascript
fetch('/')
  .then((res) => res.text())
  .then((res) => console.log(res))
```

### 2. 解析脚本资源链接

从 HTML 内容中提取所有脚本资源链接，用于后续比较：

```javascript
// 用于存储上一次获取的脚本资源链接列表，用于后续比较
let lastSrcs

// 正则表达式，用于匹配HTML中的script标签及其src属性
// 使用命名捕获组(?<src>[^"']+)来提取src属性值
const scriptReg = /\<script.*src=["'](?<src>[^"']+)/gm

/**
 * 获取最新页面中的script链接
 * 通过请求首页HTML内容，解析出所有script标签的src属性
 */
const extractNewScriptSrcs = async () => {
  // 请求首页内容，添加时间戳参数防止浏览器缓存
  const html = await fetch('/?_timestamp=' + Date.now()).then((res) =>
    res.text()
  )

  // 重置正则表达式的lastIndex，确保从头开始匹配
  scriptReg.lastIndex = 0

  let result = []
  let match

  // 循环匹配HTML中的所有script标签，提取src属性
  while ((match = scriptReg.exec(html))) {
    result.push(match.groups.src) // 将匹配到的src属性值添加到结果数组
  }

  return result // 返回所有script资源链接的数组
}
```

### 3. 检测版本更新

比较当前获取的资源链接与上一次存储的链接，判断是否有更新：

```javascript
// 检查是否有新的版本更新
const checkUpdate = async () => {
  // 获取当前服务器最新的script资源链接
  const newScripts = await extractNewScriptSrcs()

  // 如果是第一次检查（lastSrcs未初始化），则保存当前脚本列表并返回无更新
  if (!lastSrcs) {
    lastSrcs = newScripts
    return false
  }

  let result = false // 默认无更新

  // 比较脚本数量，如果数量不同则说明有更新
  if (lastSrcs.length !== newScripts.length) {
    result = true
  }

  // 逐个比较脚本链接，如果任一链接不同则说明有更新
  for (let i = 0; i < lastSrcs.length; i++) {
    if (lastSrcs[i] !== newScripts[i]) {
      result = true
      break // 发现不同立即退出循环
    }
  }

  // 更新本地存储的脚本链接列表为最新值
  lastSrcs = newScripts

  return result // 返回是否有更新的结果
}
```

### 4. 定时检查更新

设置定时器，定期检查是否有新版本：

```javascript
// 检查更新的时间间隔，单位毫秒（2000ms = 2秒）
const DURATION = 2000

// 自动刷新检查函数，实现定时检查更新的循环机制
const autoRefresh = () => {
  setTimeout(async () => {
    // 检查是否有更新
    const willUpdate = await checkUpdate()

    // 如果检测到更新，则提示用户刷新页面
    if (willUpdate) {
      // 可替换为自定义弹窗或更友好的用户界面
      const result = confirm('检测到新版本，是否刷新页面以获取最新内容？')
      if (result) {
        // 用户确认后刷新页面，加载最新资源
        location.reload()
      }
    }

    // 递归调用自身，实现持续的更新检查
    autoRefresh()
  }, DURATION) // 按设定的时间间隔执行
}

// 启动自动更新检查机制
autoRefresh()
```
