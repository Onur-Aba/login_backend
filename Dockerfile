# --- AŞAMA 1: BUILD (Derleme) ---
FROM node:18-alpine As build

# Çalışma dizinini ayarla
WORKDIR /usr/src/app

# Bağımlılık dosyalarını kopyala
COPY package*.json ./

# Tüm bağımlılıkları yükle (DevDependencies dahil, çünkü build alacağız)
RUN npm install

# Kaynak kodları kopyala
COPY . .

# TypeScript kodunu derle (dist klasörü oluşur)
RUN npm run build

# --- AŞAMA 2: PRODUCTION (Çalıştırma) ---
FROM node:18-alpine As production

# Güvenlik için NODE_ENV ayarla
ENV NODE_ENV=production

WORKDIR /usr/src/app

# Sadece production bağımlılıklarını kopyala ve yükle (Daha küçük imaj boyutu)
COPY package*.json ./
RUN npm install --only=production

# İlk aşamadan derlenmiş kodları (dist) buraya taşı
COPY --from=build /usr/src/app/dist ./dist

# Güvenlik: Root kullanıcısı yerine node kullanıcısına geç
USER node

# Uygulamayı başlat
CMD ["node", "dist/main"]