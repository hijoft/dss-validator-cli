/*
 * Copyright (C) 2016 Jan Hirsiger jan@hirsiger.org.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301  USA
 */
package ch.bfh.project2.validator.helper;

/**
 * Command-Line arguments
 * @author Jan Hirsiger jan@hirsiger.org
 */
public enum CLIArgs {
    HELP("h", "help"),
    FILE("f", "file"),
    CERTS("c", "certs"),
    POLICY("p", "policy"),
    RFORMAT("rf", "rformat"),
    RDEST("rd", "rdest"),
    DB("db","database"),
    LOTL("l", "lotl"),
    ;
    
    private final String shortArg, longArg;
    
    private CLIArgs(final String shortArg, final String longArg){
        this.shortArg = shortArg;
        this.longArg = longArg;
    }
    
    @Override
    public String toString(){
        return this.shortArg + " " + this.longArg;
    }   
    
    public String shortArg(){
        return this.shortArg;
    } 
    
    public String longArg(){
        return this.longArg;
    }    
    
}
