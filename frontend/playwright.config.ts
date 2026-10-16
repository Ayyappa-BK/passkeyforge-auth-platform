import { defineConfig } from '@playwright/test';
export default defineConfig({testDir:'./e2e',workers:1,retries:0,timeout:60000,reporter:[['list'],['html',{open:'never'}]],use:{baseURL:'http://localhost:5173',trace:'retain-on-failure'},webServer:{command:'npm run dev',url:'http://localhost:5173',reuseExistingServer:!process.env.CI}});
