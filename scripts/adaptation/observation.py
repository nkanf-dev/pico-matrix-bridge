"""Bounded retries for read-only metadata, with credential-free diagnostics."""
import json
import re
import time


class MetadataObservationError(RuntimeError):
    def __init__(self, category, attempts, service_code=None):
        self.category = category
        self.attempts = attempts
        self.service_code = service_code
        detail = f'; service code {service_code}' if service_code is not None else ''
        super().__init__(f'PICO metadata observation failed after {attempts} attempt(s): {category}{detail}')

    def diagnostic(self):
        result = {'category': self.category, 'attempts': self.attempts}
        if self.service_code is not None:
            result['serviceCode'] = self.service_code
        return result


def download_info(client, target, auth, *, attempts=3, sleep=time.sleep, report=print):
    """Retry malformed/empty business responses that the SDK transport does not retry.

    The SDK already retries transport failures. Do not multiply that budget or
    retry a package identity mismatch. Raw exception text never leaves this call.
    """
    if type(attempts) is not int or not 1 <= attempts <= 3:
        raise ValueError('Metadata observation budget must be between one and three')
    for attempt in range(1, attempts + 1):
        code = None
        try:
            return client.download_info(target, auth)
        except json.JSONDecodeError:
            category, retry = 'invalid_json', True
        except ValueError as error:
            message = str(error)
            rejected = re.fullmatch(r'PICO download info failed: (-?[0-9]{1,12}|invalid response)', message)
            if message in ('invalid PICO response', 'PICO returned incomplete APK metadata'):
                category, retry = 'incomplete_metadata', True
            elif rejected:
                code = int(rejected[1]) if rejected[1] != 'invalid response' else None
                category, retry = 'service_rejected', True
            elif message == 'PICO returned an unexpected download package':
                category, retry = 'unexpected_package', False
            else:
                raise MetadataObservationError('invalid_request_or_response', attempt) from None
        except (RuntimeError, OSError):
            category, retry = 'transport_failed', False
        if not retry or attempt == attempts:
            raise MetadataObservationError(category, attempt, code) from None
        report(json.dumps({'event': 'metadata_retry', 'attempt': attempt,
                           'category': category, **({'serviceCode': code} if code is not None else {})}))
        sleep(attempt)
