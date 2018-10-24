<?php
namespace RKA\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;

class ProxyDetectionMiddleware extends ProxyDetection
{
    /**
     * Override the request URI's scheme, host and port as determined from the proxy headers
     *
     * @param ServerRequestInterface $request PSR7 request
     * @param ResponseInterface $response     PSR7 response
     * @param callable $next                  Next middleware
     *
     * @return ResponseInterface
     */
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response, $next)
    {
        if (!$next) {
            return $response;
        }

        if (!$this->isProxyTrusted($request)) {
            return $response = $next($request, $response);
        }

        $request = $this->processRequest($request);

        return $response = $next($request, $response);
    }

    /**
     * Check that a given string is a valid IP address
     *
     * @param  string  $ip
     * @return boolean
     */
    protected function isValidIpAddress($ip)
    {
        $flags = FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6;
        if (filter_var($ip, FILTER_VALIDATE_IP, $flags) === false) {
            return false;
        }
        return true;
    }

    protected function processProtoHeader(ServerRequestInterface $request, UriInterface $uri)
    {
        if ($request->hasHeader('X-Forwarded-Proto')) {
            $scheme = $request->getHeaderLine('X-Forwarded-Proto');

            if (in_array($scheme, ['http', 'https'])) {
                return $uri->withScheme($scheme);
            }
        }
        return $uri;
    }

    protected function processPortHeader(ServerRequestInterface $request, UriInterface $uri)
    {
        if ($request->hasHeader('X-Forwarded-Port')) {
            $port = trim(current(explode(',', $request->getHeaderLine('X-Forwarded-Port'))));

            if (preg_match('/^\d+\z/', $port)) {
                return $uri->withPort((int) $port);
            }
        }
        return $uri;
    }

    protected function processHostHeader(ServerRequestInterface $request, UriInterface $uri)
    {
        if ($request->hasHeader('X-Forwarded-Host')) {
            $host = trim(current(explode(',', $request->getHeaderLine('X-Forwarded-Host'))));

            $port = null;
            if (preg_match('/^(\[[a-fA-F0-9:.]+\])(:\d+)?\z/', $host, $matches)) {
                $host = $matches[1];
                if ($matches[2]) {
                    $port = (int) substr($matches[2], 1);
                }
            } else {
                $pos = strpos($host, ':');
                if ($pos !== false) {
                    $port = (int) substr($host, $pos + 1);
                    $host = strstr($host, ':', true);
                }
            }
            $uri = $uri->withHost($host);
            if ($port) {
                $uri = $uri->withPort($port);
            }
        }
        return $uri;
    }
}
