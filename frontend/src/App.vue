<script setup lang="ts">
import TopBar from './components/TopBar.vue'
</script>

<template>
  <div class="app-shell">
    <TopBar />
    <router-view />
  </div>
</template>
