<?php

/**
 * PhalconSlayer\Framework.
 *
 * @copyright 2015-2016 Daison Carino <daison12006013@gmail.com>
 * @license   http://www.opensource.org/licenses/mit-license.php MIT
 * @link      http://docs.phalconslayer.com
 */

namespace Clarity\Support\Auth;

use InvalidArgumentException;

/**
 * Authentication handler.
 */
class Auth
{
    /**
     * Attempt to login using the provided records and the password field.
     *
     * @param  array $records
     * @param   bool    $remember
     * @return bool
     */
    public function attempt($records, $remember = false)
    {
        $password_field = config()->app->auth->{$this->guard}->password_field;

        if (isset($records[$password_field]) === false) {
            throw new InvalidArgumentException('Invalid argument for password field.');
        }

        # get the password information

        $password = $records[$password_field];
        unset($records[$password_field]);

        # build the conditions

        $first = true;
        $conditions = null;

        foreach ($records as $key => $record) {
            if (! $first) {
                $conditions .= 'AND';
            }

            $conditions .= " {$key} = :{$key}: ";

            $first = false;
        }

        # find the informations provided in the $records

        $auth_model = config()->app->auth->{$this->guard}->model;

        $records = $auth_model::find([
            $conditions,
            'bind' => $records,
        ])->getFirst();

        # check if there is no record, then return false

        if (! $records) {
            return false;
        }

        # now check if the password given is matched with the
        # existing password recorded.

        if (resolve('security')->checkHash($password, $records->{$password_field})) {
            $this->loginSession($records);
            if(!empty($remember)){
                $this->createRememberEnvironment($records);
            }

            return true;
        }

        return false;
    }

    /**
     * Redirect based on the key provided in the url.
     *
     * @return mixed|bool
     */
    public function redirectIntended()
    {
        $redirect_key = config()->app->auth->{$this->guard}->redirect_key;

        $redirect_to = resolve('request')->get($redirect_key);

        if ($redirect_to) {
            return resolve('response')->redirect($redirect_to);
        }

        return false;
    }

    /**
     * To determine if the user is logged in.
     *
     * @return bool
     */
    public function check()
    {
        if (resolve('session')->has($this->guard . '_isAuthenticated') || $this->loginWithRememberMe()){
            return true;
        }

        return false;
    }

    /**
     * Get the stored user information.
     *
     * @return mixed
     */
    public function user()
    {
        return resolve('session')->get('session')->get($this->guard . '_user');
    }
    
    /**
     * Save the User data into the Session.
     *
     * @param object $user
     */
    protected function loginSession($user){
        resolve('session')->set($this->guard . '_isAuthenticated', true);
        resolve('session')->set($this->guard . '_user', $user);
    }

    /**
     * Destroy the current auth.
     *
     * @return  bool
     */
    public function destroy()
    {
        resolve('session')->remove($this->guard . '_isAuthenticated');
        resolve('session')->remove($this->guard . '_user');
        resolve('cookies')->get($this->guard . '_RMU')->delete();
        resolve('cookies')->get($this->guard . '_RMT')->delete();

        return true;
    }

    /**
     * Creates the remember me environment settings the related cookies and generating tokens
     *
     * @param   object  $user
     * @return void
     */
    protected function createRememberEnvironment($user)
    {
        $expire = config("app.auth.{$this->guard}.expire");
        $expire = time() + ($expire ?: 60) * 60;
        $user->remember_token = resolve('crypt')->encrypt($expire);
        if ($user->save() != false) {
            resolve('cookies')->set($this->guard . '_RMU', $user->id, $expire);
            resolve('cookies')->set($this->guard . '_RMT', $user->remember_token, $expire);
        }
    }

    /**
     * Logs on using the information in the cookies
     *
     * @return  bool
     */
    protected function loginWithRememberMe()
    {
        if (resolve('cookies')->has($this->guard . '_RMU') && resolve('cookies')->has($this->guard . '_RMT')) {
            $userId = resolve('cookies')->get($this->guard . '_RMU')->getValue();
            $cookieToken = resolve('cookies')->get($this->guard . '_RMT')->getValue();
            $auth_model = config()->app->auth->{$this->guard}->model;
            $user = $auth_model::find([
                'id = :id: AND remember_token = :remember_token: AND activated = :activated:',
                'bind' => [
                    'id' => $userId,
                    'remember_token' => $cookieToken,
                    'activated' => true
                ]
            ])->getFirst();
            
            if ($user) {
                $expire = resolve('crypt')->decrypt($user->remember_token);
                if (time() < (int) $expire) {
                    $this->loginSession($user);
                    return true;
                }
            }
            resolve('cookies')->get($this->guard . '_RMU')->delete();
            resolve('cookies')->get($this->guard . '_RMT')->delete();
        }
        return false;
    }
    
    /**
     * Get|Set the guard to be used during authentication.
     *
     * @param  string  $guard
     * @return string
     */
    public function guard($guard = null)
    {
        if (! empty($guard)) {
            $guards = config('app.auth');
            if (! array_key_exists($guard, $guards)) {
                throw new InvalidArgumentException("The guard '{$guard}' is not defined");
            }
            $this->guard = $guard;
        } else {
            $this->guard = config('app.guard');
        }
        return $this->guard;
    }
    
    /**
     * Set the default guard the factory should serve.
     *
     * @param  string  $guard
     * @return void
     */
    public function shouldUse($guard)
    {
        $guards = config('app.auth');
        if (! array_key_exists($guard, $guards)) {
            throw new InvalidArgumentException("The guard '{$guard}' is not defined");
        }
        config([
            'app' => [
                'guard' => $guard
            ]
        ], true);
        $this->guard = $guard;
    }
}
