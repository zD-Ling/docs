import { defineConfig } from "vitepress";

// https://vitepress.dev/reference/site-config
export default defineConfig({
  title: "长岛冰茶的技术文档",
  description: "A VitePress Site",
  // base: "/docs/",
  head: [["link", { rel: "icon", href: "/logo.svg" }]],
  themeConfig: {
    logo: "logo.svg",
    // https://vitepress.dev/reference/default-theme-config
    nav: [
      { text: "首页", link: "/" },
      { text: "docker", 
        items:[
          {text: '安装', link: '/docker/安装.md'}
        ]
       },
    ],

    sidebar: [
      {
        text: "目录",
        items: [{ text: "docker", items:[
          {text: '安装', link: '/docker/安装.md'}
        ] }],
      },
    ],
    search: {
      provider: "local",
      options: {
        translations: {
          button: {
            buttonText: "搜索文档",
            buttonAriaLabel: "搜索文档",
          },
          modal: {
            noResultsText: "无法找到相关结果",
            resetButtonTitle: "清除查询条件",
            footer: {
              selectText: "选择",
              navigateText: "切换",
              closeText: "关闭",
            },
          },
        },
      },
    },

    // socialLinks: [
    //   { icon: "github", link: "https://github.com/vuejs/vitepress" },
    // ],

    footer: {
      copyright: "Copyright@ 2025 Long Island iced tea",
    },
    head: [["link", { rel: "icon", href: "/logo.svg" }]],
  },
});
