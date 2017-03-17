import datetime
import requests
import time

from iso8601 import iso8601
from pytz import timezone
from checks import CheckException


class SplunkSavedSearch(object):
    def __init__(self, instance_config, saved_search_instance):
        self.name = saved_search_instance['name']
        self.parameters = saved_search_instance['parameters']

        self.request_timeout_seconds = int(saved_search_instance.get('request_timeout_seconds', instance_config.default_request_timeout_seconds))
        self.search_max_retry_count = int(saved_search_instance.get('search_max_retry_count', instance_config.default_search_max_retry_count))
        self.search_seconds_between_retries = int(saved_search_instance.get('search_seconds_between_retries', instance_config.default_search_seconds_between_retries))
        self.batch_size = int(saved_search_instance.get('batch_size', instance_config.default_batch_size))

class SplunkInstanceConfig(object):

    @staticmethod
    def _get_or_default(field, obj, defaults):
        return obj.get(field, defaults[field])

    def __init__(self, instance, init_config, defaults):
        self.default_request_timeout_seconds = self._get_or_default('default_request_timeout_seconds', init_config, defaults)
        self.default_search_max_retry_count = self._get_or_default('default_search_max_retry_count', init_config, defaults)
        self.default_search_seconds_between_retries = self._get_or_default('default_search_seconds_between_retries', init_config, defaults)
        self.default_verify_ssl_certificate = self._get_or_default('default_verify_ssl_certificate', init_config, defaults)
        self.default_batch_size = self._get_or_default('default_batch_size', init_config, defaults)
        self.default_saved_searches_parallel = self._get_or_default('default_saved_searches_parallel', init_config, defaults)

        self.verify_ssl_certificate = bool(instance.get('verify_ssl_certificate', self.default_verify_ssl_certificate))
        self.base_url = instance['url']
        self.username = instance['username']
        self.password = instance['password']

    def get_auth_tuple(self):
        return self.username, self.password


class SplunkHelper():

    def _search_chunk(self, instance_config, saved_search, search_id, offset, count):
        """
        Retrieves the results of an already running splunk search, identified by the given search id.
        :param instance_config: InstanceConfig, current check configuration
        :param saved_search: current SavedSearch being processed
        :param search_id: perform a search operation on the search id
        :param offset: starting offset, begin is 0, to start retrieving from
        :param count: the maximum number of elements expecting to be returned by the API call
        :return: raw json response from splunk
        """
        search_url = '%s/services/search/jobs/%s/results?output_mode=json&offset=%s&count=%s' % (instance_config.base_url, search_id, offset, count)
        auth = instance_config.get_auth_tuple()

        response = requests.get(search_url, auth=auth, timeout=saved_search.request_timeout_seconds, verify=instance_config.verify_ssl_certificate)
        response.raise_for_status()
        retry_count = 0

        # retry until information is available.
        while response.status_code == 204: # HTTP No Content response
            if retry_count == saved_search.search_max_retry_count:
                raise CheckException("maximum retries reached for " + instance_config.base_url + " with search id " + search_id)
            retry_count += 1
            time.sleep(saved_search.search_seconds_between_retries)
            response = requests.get(search_url, auth=auth, timeout=saved_search.request_timeout_seconds, verify=instance_config.verify_ssl_certificate)
            response.raise_for_status()

        return response.json()

    def saved_search_results(self, search_id, saved_search, instance_config):
        """
        Perform a saved search, returns a list of responses that were received
        """
        # fetch results in batches
        offset = 0
        nr_of_results = None
        results = []
        while nr_of_results is None or nr_of_results == saved_search.batch_size:
            response = self._search_chunk(instance_config, saved_search, search_id, offset, saved_search.batch_size)
            # received a message?
            for message in response['messages']:
                if message['type'] == "FATAL":
                    raise CheckException("Received FATAL exception from Splunk, got: " + message['text'])

            results.append(response)
            nr_of_results = len(response['results'])
            offset += nr_of_results
        return results

    def do_post(self, url, auth, payload, request_timeout_seconds, verify_ssl_certificate):
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        resp = requests.post(url, headers=headers, data=payload, auth=auth, timeout=request_timeout_seconds, verify=verify_ssl_certificate)
        resp.raise_for_status()
        return resp


def take_required_field(field, obj):
    """
    Get a field form an object, remove its value and remove the field form the object
    """
    if field not in obj:
        raise CheckException("Missing '%s' field in result data" % field)
    value = obj[field]
    del obj[field]
    return value


def take_optional_field(field, obj):
    """
    Get a field form an object, remove its value and remove the field form the object
    """
    if field not in obj:
        return None
    value = obj[field]
    del obj[field]
    return value


def get_time_since_epoch(utc_datetime):
    utc = timezone('UTC')
    begin_epoch = datetime.datetime.utcfromtimestamp(0).replace(tzinfo = utc)
    timestamp = (utc_datetime - begin_epoch).total_seconds()
    return timestamp


def time_to_seconds(str_datetime_utc):
    """
    Converts time in utc format 2016-06-27T14:26:30.000+00:00 to seconds
    """
    parsed_datetime = iso8601.parse_date(str_datetime_utc)
    return get_time_since_epoch(parsed_datetime)


def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in xrange(0, len(l), n):
        yield l[i:i + n]
