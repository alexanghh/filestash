import React from "react";
import { currentShare } from "../../helpers/";
import "./appframe.scss";
import {MenuBar} from "./menubar";

export function AppFrame({ args, data, filename, path }) {
    let error = null;
    if (!args) {
        error = "Missing configuration. Contact your administrator";
    } else if (!args.endpoint) {
        error = "Missing endpoint configuration. Contact your administrator";
    }
    if (error !== null) {
        return (
            <div className="component_appframe">
                <div className="error">{error}</div>
            </div>
        );
    }
    return (
        <div className="component_appframe">
            <MenuBar title={filename} download={data} />
            <iframe src={args.endpoint + "?path=" + path + "&share=" + currentShare()} />
        </div>
    );
}
