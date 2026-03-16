import { env } from './config/env'
import { connectDB } from './db/pool'
import app from './app'

async function bootstrap() {
  // Validate DB connection before accepting traffic
  await connectDB()

  const server = app.listen(env.PORT, () => {
    console.log(`🚀 Auth Server running on port ${env.PORT} (${env.NODE_ENV})`)
    console.log(`   Health: http://localhost:${env.PORT}/health`)
  })

  // Graceful shutdown
  const shutdown = async (signal: string) => {
    console.log(`\n${signal} received — shutting down gracefully...`)
    server.close(async () => {
      const { db } = await import('./db/pool')
      await db.end()
      console.log('✅ Shutdown complete')
      process.exit(0)
    })
  }

  process.on('SIGTERM', () => shutdown('SIGTERM'))
  process.on('SIGINT',  () => shutdown('SIGINT'))
}

bootstrap().catch(err => {
  console.error('❌ Failed to start server:', err)
  process.exit(1)
})
