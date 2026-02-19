import SecureContent from '@/components/SecureContent';

export default function Page() {
  // В реальности эти данные придут зашифрованными с вашего FastAPI бэкенда
  const mockEncryptedData = Array(100 * 100 * 4).fill(0).map(() => Math.floor(Math.random() * 255));

  return (
    <div className="min-h-screen bg-black flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <h1 className="text-white text-xl font-light mb-8 text-center tracking-tighter">
          CONTROLLED <span className="font-bold text-blue-500">VIEWING</span> SYSTEM
        </h1>
        <SecureContent encryptedData={mockEncryptedData} />
      </div>
    </div>
  );
}
