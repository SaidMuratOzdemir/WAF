FROM node:20-alpine

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm install --legacy-peer-deps

# Copy application files
COPY . .

# Expose the port the app will run on
EXPOSE 5173

# Start the application in development mode
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
