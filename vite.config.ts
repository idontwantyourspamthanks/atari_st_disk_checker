import { defineConfig } from 'vite'
import { fileURLToPath } from 'node:url'
import vue from '@vitejs/plugin-vue'
import { viteSingleFile } from 'vite-plugin-singlefile'

export default defineConfig({
	// Relative asset paths so the built `dist/` folder can be opened from
	// `file://`, served from any subdirectory, or zipped and shipped.
	// Vite's default is `/`, which only works at a domain root.
	base: './',
	plugins: [
		vue(),
		// Inline every JS and CSS chunk into index.html so the result is a
		// single self-contained file. This is the fix for Firefox-over-file://,
		// which blocks <script type="module" src="..."> under CORS even when
		// the path is relative. With everything inlined as an inline module
		// script, no fetch happens and Firefox is happy.
		viteSingleFile(),
	],
	resolve: {
		alias: {
			'@': fileURLToPath(new URL('./src', import.meta.url)),
		},
	},
})
