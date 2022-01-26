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

require 'ronin/php/lfi/lfi'

module URI
  class HTTP < Generic

    #
    # @see Ronin::PHP::LFI.scan
    #
    def lfi_scan(options={})
      Ronin::PHP::LFI.scan(self,options)
    end

    #
    # Attempts to find the first LFI vulnerability of the URL.
    #
    # @param [Hash] options
    #   Additional options.
    #
    # @option options [Range] :up
    #   The number of directories to attempt traversing up.
    #
    # @return [Ronin::PHP::LFI]
    #   The first LFI vulnerability found.
    #
    def first_lfi(options={})
      Ronin::PHP::LFI.scan(self,options).first
    end

    #
    # Determines if the URL is vulnerable to Local File Inclusion (LFI).
    #
    # @param [Hash] options
    #   Additional options.
    #
    # @option options [Range] :up
    #   The number of directories to attempt traversing up.
    #
    # @return [Boolean]
    #   Specifies whether the URL is vulnerable to LFI.
    #
    def has_lfi?(options={})
      !(first_lfi(options).nil?)
    end

    #
    # @deprecated Use {#lfi_scan} instead.
    #
    def test_lfi(*arguments,&block)
      lfi_scan(*arguments,&block)
    end

    #
    # @deprecated Use {#first_lfi} instead.
    #
    def lfi(*arguments,&block)
      first_lfi(*arguments,&block)
    end

  end
end
