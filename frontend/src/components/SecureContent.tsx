'use client';

import { useEffect, useState, useRef } from 'react';

// Типизация для нашего Wasm-модуля
type WasmModule = typeof import('../../wasm/pkg/wasm_watermark');

export default function SecureContent({ encryptedData }: { encryptedData: number[] }) {
    const [wasm, setWasm] = useState<WasmModule | null>(null);
    const [viewer, setViewer] = useState<any>(null);
    const [isReady, setIsReady] = useState(false);
    const canvasRef = useRef<HTMLCanvasElement>(null);

    // 1. Инициализация Wasm при загрузке компонента
    useEffect(() => {
        const loadWasm = async () => {
            try {
                // Динамически импортируем сгенерированный JS-мост
                const module = await import('../../wasm/pkg/wasm_watermark');
                await module.default(); // Инициализируем бинарный файл .wasm

                setWasm(module);
                setViewer(new module.SecureViewer());
                setIsReady(true);
                console.log("🛡️ DRM Engine: WebAssembly Secure Enclave Loaded");
            } catch (err) {
                console.error("❌ Failed to load Wasm module:", err);
            }
        };

        loadWasm();
    }, []);

    const handleUnlock = async (key: string) => {
        if (!viewer || !wasm) return;

        // Вызов метода из Rust
        if (viewer.verify_key(key)) {
            try {
                const decrypted = viewer.decrypt_content(new Uint8Array(encryptedData));
                renderToCanvas(decrypted);
            } catch (e) {
                alert("Ошибка дешифровки: Ключ валиден, но данные повреждены.");
            }
        } else {
            alert("Доступ запрещен: Неверный лицензионный ключ.");
        }
    };

    const renderToCanvas = (data: Uint8Array) => {
        const ctx = canvasRef.current?.getContext('2d');
        if (!ctx) return;

        // Создаем изображение прямо из защищенного буфера памяти Wasm
        const imageData = new ImageData(new Uint8ClampedArray(data), 100, 100);
        ctx.putImageData(imageData, 0, 0);
    };

    if (!isReady) return <div className="animate-pulse text-slate-500">Загрузка защищенного окружения...</div>;

    return (
        <div className="space-y-4 bg-slate-900 p-6 rounded-xl border border-slate-800 shadow-2xl">
            <div className="flex items-center gap-2 mb-2">
                <div className="w-2 h-2 rounded-full bg-green-500 shadow-[0_0_10px_#22c55e]"></div>
                <span className="text-xs font-mono text-green-500 uppercase tracking-widest">Secure Enclave Active</span>
            </div>

            <canvas
                ref={canvasRef}
                width={100}
                height={100}
                className="w-full aspect-square bg-black rounded border border-slate-700 image-render-pixelated"
                onContextMenu={(e) => e.preventDefault()}
            />

            <div className="flex gap-2">
                <input
                    type="password"
                    id="key-input"
                    placeholder="Лицензионный ключ"
                    className="flex-1 bg-slate-950 border border-slate-800 p-2 rounded text-sm focus:border-blue-500 outline-none transition"
                />
                <button
                    onClick={() => handleUnlock((document.getElementById('key-input') as HTMLInputElement).value)}
                    className="bg-blue-600 hover:bg-blue-500 px-4 py-2 rounded text-sm font-bold transition-all active:scale-95"
                >
                    Unlock
                </button>
            </div>
        </div>
    );
}
