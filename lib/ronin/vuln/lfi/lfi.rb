#
# ronin-vuln-lfi - A small Ruby library to test for Local File Inclusion (LFI)
# vulnerabilities.
#
# Copyright (c) 2007-2022 Hal Brodigan (postmodern.mod3 at gmail.com)
#
# ronin-vuln-lfi is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ronin-vuln-lfi is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with ronin-vuln-lfi.  If not, see <https://www.gnu.org/licenses/>.
#

require 'ronin/vuln/lfi/exceptions/unknown_signature'
require 'ronin/vuln/lfi/signature'
require 'ronin/vuln/lfi/signatures'
require 'ronin/network/http'
require 'ronin/web/spider'
require 'ronin/path'

require 'uri/query_params'

module Ronin
  module Vuln
    class LFI

      # Maximum number of directories to escape
      MAX_UP = 15

      # The URL which is vulnerable
      attr_reader :url

      # The vulnerable query param
      attr_accessor :param

      # The path prefix
      attr_accessor :prefix

      # Number of directories to traverse up
      attr_accessor :up

      # Whether to terminate the LFI path with a null byte
      attr_accessor :terminate

      # Targeted Operating System (OS)
      attr_accessor :os

      #
      # Creates a new LFI object.
      #
      # @param [String, URI::HTTP] url
      #   The URL to exploit.
      #
      # @param [String, Symbol] param
      #   The query parameter to perform LFI on.
      #
      # @param [Hash] options
      #
      # @option options [String] :prefix
      #   Optional prefix for any Local File Inclusion path.
      #
      # @option options [Integer] :up (0)
      #   Number of directories to escape up.
      #
      # @option options [Boolean] :terminate (true)
      #   Specifies whether to terminate the LFI path with a null byte.
      #
      # @option options [String] :os
      #   Operating System to specifically target.
      #
      def initialize(url,param,options={})
        @url = url
        @param = param

        @prefix = options[:prefix]
        @up = (options[:up] || 0)

        if options.has_key?(:terminate)
          @terminate = options[:terminate]
        else
          @terminate = true
        end

        @os = options[:os]
      end

      #
      # Scans the URL for LFI vulnerabilities.
      #
      # @param [URI::HTTP, String] url
      #   The URL to scan.
      #
      # @param [Hash] options
      #   Additional options.
      #
      # @option options [Range] :up
      #   The number of directories to attempt traversing up.
      #
      # @yield [lfi]
      #   The given block will be passed each discovered LFI vulnerability.
      #
      # @yieldparam [LFI] lfi
      #   A discovered LFI vulnerability.
      #
      # @return [Enumerator]
      #   If no block is given, an enumerator object will be returned.
      #
      # @since 0.2.0
      #
      def LFI.scan(url,options={})
        return enum_for(:scan,url,options) unless block_given?

        url = URI(url)
        up = (options[:up] || (0..MAX_UP))

        url.query_params.each_key do |param|
          lfi = Ronin::Vuln::LFI.new(url,param)

          up.each do |n|
            lfi.up = n

            if lfi.vulnerable?(options)
              yield lfi
              break
            end
          end
        end
      end

      #
      # @return [Boolean]
      #   Specifies whether the LFI path will be terminated with a null
      #   byte.
      #
      def terminate?
        @terminate == true
      end

      #
      # Builds a Local File Inclusion URL which includes a local path.
      #
      # @param [String] path
      #   The path of the local file to include.
      #
      # @return [URI::HTTP]
      #   The URL for the Local File Inclusion.
      #
      def url_for(path)
        escape = (@prefix || Path.up(@up))
        full_path = escape.join(path.to_s)
        full_path = "#{full_path}\0" if terminate?

        new_url = URI(@url)
        new_url.query_params[@param.to_s] = full_path

        return new_url
      end

      #
      # Requests the contents of a local file.
      #
      # @param [String] path
      #   The path of the local file to request.
      # 
      # @param [Hash] options
      #   Additional HTTP options to use when requesting the local file.
      #
      # @option options [Symbol] :method (:get)
      #   The HTTP method to request the local file. May be either
      #   `:get` or `:post`.
      #
      # @return [String]
      #   The body of the response.
      #
      # @see Net.http_request
      # @see Net.http_post_body
      #
      def get(path,options={})
        options  = options.merge(:url => url_for(path))
        response = Net.http_request(options)

        return response.body
      end

      #
      # Requests the contents of a local file.
      #
      # @return [String]
      #   The HTTP response from the LFI request.
      #
      # @see get
      #
      def include(path,options={})
        get(path,options)
      end

      #
      # @return [Boolean]
      #   Specifies whether the URL and query parameter are vulnerable
      #   to LFI.
      #
      def vulnerable?(options={})
        Signature.tests.each do |sig|
          inclusion_of(sig) do |file|
            return true
          end
        end

        return false
      end

      #
      # Converts the LFI to a String.
      #
      # @return [String]
      #   The URL being exploited.
      #
      def to_s
        @url.to_s
      end

      protected

      #
      # @param [Signature] sig
      #   A file signature for a known file.
      #
      # @return [Array<String>]
      #   The available paths of the specified file signature.
      #
      def paths_of(sig)
        if @os
          return sig.paths_for(@os)
        else
          return sig.all_paths
        end
      end

    end
  end
end
