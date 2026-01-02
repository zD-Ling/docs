import { defineConfig } from 'vitepress'

// https://vitepress.dev/reference/site-config
export default defineConfig({
  title: '长岛冰茶的技术文档',
  description: '长岛冰茶的技术文档',
  // base: "/docs/",
  head: [
    [
      'link',
      {
        rel: 'icon',
        href: '/logo.svg'
      }
    ],
    [
      'script',
      {},
      `
      var _hmt = _hmt || [];
      (function() {
        var hm = document.createElement("script");
        hm.src = "https://hm.baidu.com/hm.js?c6e7bb490d40ae8a96902955d50d5e5f";
        var s = document.getElementsByTagName("script")[0]; 
        s.parentNode.insertBefore(hm, s);
      })();
      `
    ]
  ],
  themeConfig: {
    logo: 'logo.svg',
    // https://vitepress.dev/reference/default-theme-config
    outlineTitle: '页面导航',
    returnToTopLabel: '返回顶部',
    sidebarMenuLabel: '菜单',
    darkModeSwitchLabel: '切换主题',
    darkModeSwitchTitle: '切换主题',
    outline: [2, 3, 4, 5, 6],
    nav: [
      {
        text: '首页',
        link: '/'
      },
      {
        text: '前端',
        items: [
          {
            text: '开发技巧',
            link: '/frontend/tips/发布订阅-不一样的设计模式.md'
          }
        ]
      },
      {
        text: 'Spring',
        items: [
          {
            text: 'Spring Security',
            link: '/Spring/Spring_Security.md'
          }
        ]
      },
      {
        text: 'docker',
        items: [
          { text: '安装', link: '/docker/安装.md' },
          { text: '软件部署', link: '/docker/软件部署.md' }
        ]
      }
    ],

    sidebar: {
      '/frontend/tips/': [
        {
          items: [
            {
              text: '发布订阅-不一样的设计模式',
              link: '/frontend/tips/发布订阅-不一样的设计模式.md'
            }
          ]
        }
      ],
      '/Spring/': [
        {
          items: [
            {
              text: 'Spring',
              items: [
                {
                  text: 'Spring Security',
                  link: '/Spring/Spring_Security.md'
                }
              ]
            }
          ]
        }
      ],
      '/docker/': [
        {
          items: [
            {
              text: 'docker',
              items: [
                {
                  text: '安装',
                  link: '/docker/安装.md'
                },
                {
                  text: '软件部署',
                  link: '/docker/软件部署.md'
                }
              ]
            }
          ]
        }
      ]
    },
    search: {
      provider: 'local',
      options: {
        translations: {
          button: {
            buttonText: '搜索文档',
            buttonAriaLabel: '搜索文档'
          },
          modal: {
            noResultsText: '无法找到相关结果',
            resetButtonTitle: '清除查询条件',
            footer: {
              selectText: '选择',
              navigateText: '切换',
              closeText: '关闭'
            }
          }
        }
      }
    },

    // socialLinks: [
    //   { icon: "github", link: "https://github.com/vuejs/vitepress" },
    // ],

    footer: {
      copyright: 'Copyright@ 2025 - 2026 Long Island iced tea'
    },
    head: [['link', { rel: 'icon', href: '/logo.svg' }]]
  }
})
