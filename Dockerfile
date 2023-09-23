FROM node:20-alpine3.17

WORKDIR /usr/src/app

COPY package*.json ./

RUN npm install

COPY . .

RUN npx prisma generate

RUN npm run build

EXPOSE 8000

CMD ["npm", "run", "start:prod"]