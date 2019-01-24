<?php

namespace Clarity\Support\Auth;

trait ThrottlesLogins
{
    public $_guard = 'user';
    /**
     * Determine if the user has too many failed login attempts.
     *
     * @param  $request
     * @return bool
     */
    protected function hasTooManyLoginAttempts($request)
    {
        return $this->limiter()->tooManyAttempts(
            $this->throttleKey($request), $this->maxAttempts()
            );
    }
    
    /**
     * Increment the login attempts for the user.
     *
     * @param  $request
     * @return void
     */
    protected function incrementLoginAttempts($request)
    {
        $this->limiter()->hit(
            $this->throttleKey($request), $this->decayMinutes()
        );
    }
    
    /**
     * Clear the login locks for the given user credentials.
     *
     * @param  $request
     * @return void
     */
    protected function clearLoginAttempts($request)
    {
        $this->limiter()->clear($this->throttleKey($request));
    }
    
    
    /**
     * Get the throttle key for the given request.
     *
     * @param  $request
     * @return string
     */
    protected function throttleKey($request)
    {
        return strtolower($this->_guard.'|'.$request->get($this->username())).'|'.$request->getClientAddress();
    }
    
    /**
     * Get the login username to be used by the controller.
     *
     * @return string
     */
    public function username(){
        return 'email';
    }
    
    /**
     * Get the rate limiter instance.
     *
     * @return Clarity\Support\Auth\RateLimiter
     */
    protected function limiter()
    {
        return new RateLimiter();
    }
    
    /**
     * Get the maximum number of attempts to allow.
     *
     * @return int
     */
    public function maxAttempts()
    {
        return property_exists($this, 'maxAttempts') ? $this->maxAttempts : 5;
    }
    
    /**
     * Get the number of seconds to throttle for.
     *
     * @return int
     */
    public function decayMinutes()
    {
        return property_exists($this, 'decayMinutes') ? $this->decayMinutes : 2;
    }
}
