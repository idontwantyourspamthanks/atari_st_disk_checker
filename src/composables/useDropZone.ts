import { ref, readonly, onMounted, onUnmounted, type DeepReadonly, type Ref } from 'vue'

// Module-level singleton state. The window has exactly one drop handler at a
// time — whichever view is active registers its onFiles via useDropHandler.
const isDragOver = ref(false)
const activeHandler: { fn: ((files: File[]) => void) | null } = { fn: null }

// Track nested dragenter/leave so the overlay doesn't flicker when the drag
// moves between child elements.
let dragDepth = 0

function onDragEnter(e: DragEvent) {
	// Only react to drags that include files (e.g. dragging text selections
	// from the page itself should not trigger the overlay).
	if (!e.dataTransfer || !Array.from(e.dataTransfer.types).includes('Files')) return
	e.preventDefault()
	dragDepth++
	isDragOver.value = true
}

function onDragOver(e: DragEvent) {
	if (!e.dataTransfer || !Array.from(e.dataTransfer.types).includes('Files')) return
	// preventDefault is required on dragover for the drop event to fire.
	e.preventDefault()
	e.dataTransfer.dropEffect = 'copy'
}

function onDragLeave(e: DragEvent) {
	e.preventDefault()
	dragDepth = Math.max(0, dragDepth - 1)
	if (dragDepth === 0) isDragOver.value = false
}

function onDrop(e: DragEvent) {
	e.preventDefault()
	dragDepth = 0
	isDragOver.value = false
	if (!e.dataTransfer?.files.length) return
	if (activeHandler.fn) {
		activeHandler.fn(Array.from(e.dataTransfer.files))
	}
}

/**
 * Mount hook for the App shell. Sets up window-level drag/drop listeners
 * and exposes `isDragOver` for rendering a full-window overlay.
 *
 * Call exactly once, in App.vue.
 */
export function useGlobalDropZone(): {
	isDragOver: DeepReadonly<Ref<boolean>>
} {
	onMounted(() => {
		window.addEventListener('dragenter', onDragEnter)
		window.addEventListener('dragover', onDragOver)
		window.addEventListener('dragleave', onDragLeave)
		window.addEventListener('drop', onDrop)
	})
	onUnmounted(() => {
		window.removeEventListener('dragenter', onDragEnter)
		window.removeEventListener('dragover', onDragOver)
		window.removeEventListener('dragleave', onDragLeave)
		window.removeEventListener('drop', onDrop)
	})

	return { isDragOver: readonly(isDragOver) }
}

/**
 * View-level hook. Registers a handler that receives any files dropped on
 * the window while the view is mounted. Replaces whatever handler was
 * previously registered.
 */
export function useDropHandler(fn: (files: File[]) => void): void {
	onMounted(() => { activeHandler.fn = fn })
	onUnmounted(() => {
		if (activeHandler.fn === fn) activeHandler.fn = null
	})
}
