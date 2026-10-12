import { removeTempDirs } from './fixtures.js';

// Registered through `setupFilesAfterEnv`, so every test file cleans up the
// temporary directories it asked for without each one remembering to.
afterAll(async () => {
  await removeTempDirs();
});
