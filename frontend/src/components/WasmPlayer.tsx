'use client';
import { useEffect, useRef, useState } from 'react';
import init, { SecureViewer } from '../../wasm/pkg/wasm_watermark';

export default function WasmPlayer({ encryptedData }: { encryptedData: number[] }) {
    const canvasRef = useRef<HTMLCanvasElement>(null);
    const [viewer, setViewer] = useState<SecureViewer | null>(null);

    useEffect(() => {
        init().then(() => setViewer(new SecureViewer()));
    }, []);

    const handleUnlock = (key: string) => {
        if (!viewer) return;

        // Вызываем скрытую логику в Wasm
        if (viewer.verify_key(key)) {
            const rawData = viewer.decrypt_content(new Uint8Array(encryptedData));
            renderToCanvas(rawData);
        } else {
            alert("Критическая ошибка доступа");
        }
    };

    const renderToCanvas = (data: Uint8Array) => {
        const ctx = canvasRef.current?.getContext('2d');
        if (!ctx) return;

        // Логика отрисовки пикселей напрямую из Wasm буфера
        const imgData = new ImageData(new Uint8ClampedArray(data), 100, 100);
        ctx.putImageData(imgData, 0, 0);
    };

    return (
        <div className="border-2 border-slate-700 p-4 rounded-lg bg-black">
            <canvas ref={canvasRef} width={100} height={100} className="mx-auto bg-slate-800" />
            <div className="mt-4 flex gap-2">
                <input
                    id="license-key"
                    type="password"
                    placeholder="Enter License Key"
                    className="bg-slate-900 border border-slate-600 px-2 py-1 text-sm rounded"
                />
                <button
                    onClick={() => handleUnlock((document.getElementById('license-key') as HTMLInputElement).value)}
                    className="bg-blue-600 px-4 py-1 rounded text-sm hover:bg-blue-500"
                >
                    Unlock
                </button>
            </div>
        </div>
    );
}
