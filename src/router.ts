import { createRouter, createWebHashHistory } from 'vue-router'

const routes = [
	{
		path: '/',
		name: 'home',
		component: () => import('./views/HomeView.vue'),
	},
	{
		path: '/text',
		name: 'text',
		component: () => import('./views/TextView.vue'),
	},
	{
		path: '/scan',
		name: 'scan',
		component: () => import('./views/ScanView.vue'),
	},
]

export default createRouter({
	// Hash history so the single-file build works under file://.
	// createWebHistory would push the browser to file:///text, which 404s.
	history: createWebHashHistory(),
	routes,
})
