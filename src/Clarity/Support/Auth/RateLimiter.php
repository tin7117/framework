<?php

namespace Clarity\Support\Auth;

class RateLimiter
{

    /**
     * The cache store implementation.
     *
     * @var Phalcon\Cache\Backend
     */
    protected $cache;

    /**
     * Create a new rate limiter instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->cache = resolve('cache');
    }

    /**
     * Determine if the given key has been "accessed" too many times.
     *
     * @param  string  $key
     * @param  int  $maxAttempts
     * @return bool
     */
    public function tooManyAttempts($key, $maxAttempts)
    {
        if ($this->attempts($key) >= $maxAttempts) {
            if ($this->cache->exists($key.':timer') && $this->availableIn($key) > 0) {
                return true;
            }

            $this->resetAttempts($key);
        }

        return false;
    }

    /**
     * Increment the counter for a given key for a given decay time.
     *
     * @param  string  $key
     * @param  float|int  $decayMinutes
     * @return int
     */
    public function hit($key, $decayMinutes = 1)
    {
        $this->cache->save(
            $key.':timer', $this->availableAt($decayMinutes * 3600), $decayMinutes * 3600
        );
        
        $hits = (int) $this->attempts($key) + 1;

        $this->cache->save($key, $hits, $decayMinutes * 3600);

        return $hits;
    }

    /**
     * Get the number of attempts for the given key.
     *
     * @param  string  $key
     * @return mixed
     */
    public function attempts($key)
    {
        return (int)$this->cache->get($key);
    }

    /**
     * Reset the number of attempts for the given key.
     *
     * @param  string  $key
     * @return mixed
     */
    public function resetAttempts($key)
    {
        return $this->cache->delete($key);
    }

    /**
     * Get the number of retries left for the given key.
     *
     * @param  string  $key
     * @param  int  $maxAttempts
     * @return int
     */
    public function retriesLeft($key, $maxAttempts)
    {
        $attempts = $this->attempts($key);

        return $maxAttempts - $attempts;
    }

    /**
     * Clear the hits and lockout timer for the given key.
     *
     * @param  string  $key
     * @return void
     */
    public function clear($key)
    {
        $this->resetAttempts($key);

        $this->cache->delete($key.':timer');
    }

    /**
     * Get the number of seconds until the "key" is accessible again.
     *
     * @param  string  $key
     * @return int
     */
    public function availableIn($key)
    {
        return $this->cache->get($key.':timer') - $this->currentTime();
    }
    
    /**
     * Get the number of seconds until the "key" is accessible again.
     *
     * @param  string  $key
     * @return int
     */
    public function availableAt($seconds)
    {
        return $this->currentTime() + $seconds;
    }
    
    /**
    * Get the current system time as a UNIX timestamp.
    *
    * @return int
    */
    protected function currentTime()
    {
        return time();
    }
}
