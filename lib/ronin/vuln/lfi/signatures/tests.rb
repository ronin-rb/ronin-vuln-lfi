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

require 'ronin/vuln/lfi/signature'

module Ronin
  module Vuln
    class LFI
      Signature.test do |sig|
        sig.paths['Linux'] = ['/etc/group']
        sig.paths['Solaris'] = ['/etc/group']

        sig.recognizor = /root:/
      end

      Signature.test do |sig|
        sig.paths['Windows'] = ['/boot.ini']

        sig.recognizor = /\[boot loader\]/
      end
    end
  end
end
