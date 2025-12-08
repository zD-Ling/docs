<!-- .vitepress/theme/MyLayout.vue -->
<script setup lang="ts">
import DefaultTheme from "vitepress/theme";
import { useData } from "vitepress";
import { nextTick, provide } from "vue";

const { isDark } = useData();

// 判断是否能使用 startViewTransition
const enableTransitions = () => {
  return (
    "startViewTransition" in document &&
    window.matchMedia("(prefers-reduced-motion: no-preference)").matches
  );
};
// 切换动画
const toggleDark = (isDark) => {
  provide(
    "toggle-appearance",
    async ({ clientX: x, clientY: y }: MouseEvent) => {
      //如果不支持动效直接切换
      if (!enableTransitions()) {
        isDark.value = !isDark.value;
        return;
      }
      document.documentElement.style.setProperty("--darkX", x + "px");
      document.documentElement.style.setProperty("--darkY", y + "px");
      // 原生的视图转换动画 https://developer.mozilla.org/zh-CN/docs/Web/API/Document/startViewTransition
      // pnpm add -D @types/dom-view-transitions 解决 document.startViewTransition 类型错误的问题
      await document.startViewTransition(async () => {
        isDark.value = !isDark.value;
        await nextTick();
      }).ready;
    }
  );
};

toggleDark(isDark);
</script>

<template>
  <DefaultTheme.Layout>
    <!-- 这里是已有的插槽组件 -->
  </DefaultTheme.Layout>
</template>

<style>
/**
* 黑暗模式切换动画
* -------------------------------------------------------------------------- */
::view-transition-old(*) {
  animation: none;
}
::view-transition-new(*) {
  animation: globalDark 0.5s ease-in;
}

@keyframes globalDark {
  from {
    clip-path: circle(0% at var(--darkX) var(--darkY));
  }
  to {
    clip-path: circle(100% at var(--darkX) var(--darkY));
  }
}

/**
* 黑暗模式下图片低亮度化
* -------------------------------------------------------------------------- */
.dark img {
  filter: brightness(0.8);
}
</style>
